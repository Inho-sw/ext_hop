#!/usr/bin/env python3
"""Summarise VM traffic captured by Start-HopCapture.ps1 and search it for a document canary.

Usage:
  python analyze_capture.py CAPTURE_DIR_OR_FILES... --vm-mac 00-15-5D-xx-xx-xx
      [--canary HOPCANARY-... | --canary-file canary.txt]
      [--wfp-csv wfp-connections.csv] [--out report.md]

Inputs are pcap/pcapng files (pktmon etl2pcap output or dumpcap). Duplicate frames that pktmon
records at several vSwitch layers are collapsed. With --wfp-csv (from Export-HopAuditData.ps1)
each remote address is attributed to the Windows executables that connected to it.
Exit code 2 when the canary is found anywhere, 0 otherwise.
"""
import argparse
import collections
import csv
import datetime
import hashlib
import ipaddress
import pathlib
import sys

from pcapread import decode, read_packets
from protocols import canary_needles, parse_dns, parse_http_request, parse_sni

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
HOP_PROCESSES = ("hop-desktop.exe", "msedgewebview2.exe")
DEDUP_WINDOW = 0.05  # seconds: identical IP packets closer than this are pktmon duplicates


def capture_files(paths):
    for raw in paths:
        path = pathlib.Path(raw)
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix.lower() in (".pcap", ".pcapng"))
        else:
            yield path


def is_local(addr):
    ip = ipaddress.ip_address(addr)
    return ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_loopback or ip.is_unspecified


class Analyzer:
    def __init__(self, vm_mac, token):
        self.vm_mac = vm_mac.upper().replace(":", "-") if vm_mac else None
        self.needles = canary_needles(token) if token else {}
        self.tail_len = max((len(n) for n in self.needles.values()), default=1) - 1
        self.recent = collections.OrderedDict()
        self.stats = collections.Counter()
        self.endpoints = {}
        self.ip_names = collections.defaultdict(set)
        self.dns_queries = collections.Counter()
        self.sni = collections.Counter()
        self.http = collections.Counter()
        self.tails = {}
        self.hits = []
        self.first_ts = self.last_ts = None

    def is_duplicate(self, ts, ip_bytes):
        digest = hashlib.blake2b(ip_bytes, digest_size=12).digest()
        while self.recent and ts - next(iter(self.recent.values())) > DEDUP_WINDOW:
            self.recent.popitem(last=False)
        if digest in self.recent:
            return True
        self.recent[digest] = ts
        return False

    def direction(self, pkt):
        if self.vm_mac:
            if pkt["src_mac"] == self.vm_mac:
                return "out"
            if pkt["dst_mac"] == self.vm_mac:
                return "in"
        if is_local(pkt["src"]) and not is_local(pkt["dst"]):
            return "out"
        if is_local(pkt["dst"]) and not is_local(pkt["src"]):
            return "in"
        return "out" if self.vm_mac is None else None

    def feed(self, ts, linktype, frame):
        self.stats["frames"] += 1
        pkt = decode(linktype, frame)
        if not pkt:
            self.stats["non_ip"] += 1
            return
        if self.is_duplicate(ts, pkt["ip_bytes"]):
            self.stats["duplicates"] += 1
            return
        direction = self.direction(pkt)
        if direction is None:
            self.stats["not_vm"] += 1
            return
        self.stats["packets"] += 1
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        remote, rport = (pkt["dst"], pkt["dport"]) if direction == "out" else (pkt["src"], pkt["sport"])
        self.account(ts, pkt, direction, remote, rport)
        self.inspect(ts, pkt, direction, remote, rport)

    def account(self, ts, pkt, direction, remote, rport):
        ep = self.endpoints.setdefault(remote, {
            "out": 0, "in": 0, "packets": 0, "ports": set(), "protos": set(), "first": ts, "last": ts})
        ep[direction] += len(pkt["ip_bytes"])
        ep["packets"] += 1
        ep["protos"].add(PROTO_NAMES.get(pkt["proto"], str(pkt["proto"])))
        if rport is not None:
            ep["ports"].add(rport)
        ep["first"], ep["last"] = min(ep["first"], ts), max(ep["last"], ts)

    def inspect(self, ts, pkt, direction, remote, rport):
        payload = pkt["payload"]
        if not payload:
            return
        if pkt["proto"] == 17 and 53 in (pkt["sport"], pkt["dport"]):
            queries, answers = parse_dns(payload)
            if pkt["dport"] == 53:
                self.dns_queries.update(queries)
            for name, addr in answers:
                self.ip_names[addr].add(name)
        if pkt["proto"] == 6 and direction == "out":
            sni = parse_sni(payload)
            if sni:
                self.sni[sni] += 1
                self.ip_names[remote].add(sni)
            request = parse_http_request(payload)
            if request:
                self.http[f"{remote}:{rport} {request}"] += 1
        if self.needles:
            self.scan_canary(ts, pkt, direction, remote, rport, payload)

    def scan_canary(self, ts, pkt, direction, remote, rport, payload):
        key = (pkt["proto"], pkt["src"], pkt["sport"], pkt["dst"], pkt["dport"])
        tail = self.tails.get(key, b"")
        data = tail + payload
        for name, needle in self.needles.items():
            # 앞 패킷 꼬리 안에만 있는 일치는 이미 셌으므로, 새 payload 와 겹치는 일치만 센다.
            if data.find(needle, max(0, len(tail) - len(needle) + 1)) >= 0:
                self.hits.append((ts, direction, remote, rport, PROTO_NAMES.get(pkt["proto"], pkt["proto"]), name))
        self.tails[key] = data[-self.tail_len:] if self.tail_len else b""


def load_wfp(path):
    apps = collections.defaultdict(set)
    with open(path, encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            exe = (row.get("Application") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
            for column in ("DestAddress", "SourceAddress"):
                if row.get(column):
                    apps[row[column]].add(exe)
    return apps


def fmt_time(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%m-%d %H:%M:%S") if ts else "-"


def write_report(an, apps, token, out):
    eps = sorted(an.endpoints.items(), key=lambda kv: kv[1]["out"] + kv[1]["in"], reverse=True)
    lines = ["# HOP 감시 캡처 분석", ""]
    lines += [f"- 기간: {fmt_time(an.first_ts)} ~ {fmt_time(an.last_ts)}",
              f"- 프레임 {an.stats['frames']:,} / 중복 제거 후 VM 패킷 {an.stats['packets']:,} "
              f"(중복 {an.stats['duplicates']:,}, 비IP {an.stats['non_ip']:,})",
              f"- 원격 주소 {len(eps)}개, DNS 질의 이름 {len(an.dns_queries)}개, TLS SNI {len(an.sni)}개", ""]
    lines += ["## 카나리 검색", ""]
    if not token:
        lines.append("카나리 미지정 (--canary)")
    elif an.hits:
        lines.append(f"**발견 {len(an.hits)}건** — 문서 내용이 네트워크로 나갔을 가능성. 아래 연결을 즉시 확인할 것.")
        lines += ["", "| 시각 | 방향 | 원격 | 프로토콜 | 인코딩 |", "|---|---|---|---|---|"]
        lines += [f"| {fmt_time(t)} | {d} | {r}:{p} | {pr} | {n} |" for t, d, r, p, pr, n in an.hits[:200]]
    else:
        lines.append(f"`{token}` 원문/UTF-16/Base64/Hex 형태 모두 **발견되지 않음** (평문 구간 기준; TLS 내부는 암호화되어 검색 불가)")
    hop_eps = [(ip, ep) for ip, ep in eps if any(a in HOP_PROCESSES for a in apps.get(ip, ()))]
    lines += ["", "## HOP 프로세스가 연결한 원격 주소 (WFP 5156 기준)", ""]
    if not apps:
        lines.append("--wfp-csv 미지정: 프로세스 귀속 불가")
    elif not hop_eps:
        lines.append("없음")
    lines += _endpoint_table(hop_eps, an, apps) if hop_eps else []
    lines += ["", "## 전체 원격 주소 (트래픽 많은 순)", ""] + _endpoint_table(eps[:150], an, apps)
    lines += ["", "## DNS 질의", ""] + [f"- {n} ({c})" for n, c in an.dns_queries.most_common()]
    lines += ["", "## TLS SNI", ""] + [f"- {n} ({c})" for n, c in an.sni.most_common()]
    lines += ["", "## 평문 HTTP 요청", ""] + ([f"- {r} ({c})" for r, c in an.http.most_common(200)] or ["없음"])
    pathlib.Path(out).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _endpoint_table(rows, an, apps):
    table = ["| 원격 주소 | 이름(DNS/SNI) | 포트 | 송신 B | 수신 B | 처음 | 마지막 | 프로세스 |",
             "|---|---|---|---:|---:|---|---|---|"]
    for ip, ep in rows:
        names = ", ".join(sorted(an.ip_names.get(ip, ())))[:80]
        ports = ",".join(str(p) for p in sorted(ep["ports"])[:6])
        procs = ", ".join(sorted(apps.get(ip, ())))[:60]
        table.append(f"| {ip} | {names} | {ports} | {ep['out']:,} | {ep['in']:,} | "
                     f"{fmt_time(ep['first'])} | {fmt_time(ep['last'])} | {procs} |")
    return table


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--vm-mac")
    parser.add_argument("--canary")
    parser.add_argument("--canary-file")
    parser.add_argument("--wfp-csv")
    parser.add_argument("--out", default="capture-report.md")
    args = parser.parse_args(argv)
    token = args.canary or (pathlib.Path(args.canary_file).read_text(encoding="utf-8-sig").strip()
                            if args.canary_file else None)
    analyzer = Analyzer(args.vm_mac, token)
    for path in capture_files(args.inputs):
        print(f"reading {path}", file=sys.stderr)
        for ts, linktype, frame in read_packets(path):
            analyzer.feed(ts, linktype, frame)
    apps = load_wfp(args.wfp_csv) if args.wfp_csv else {}
    write_report(analyzer, apps, token, args.out)
    print(f"packets={analyzer.stats['packets']} endpoints={len(analyzer.endpoints)} "
          f"canary_hits={len(analyzer.hits)} report={args.out}")
    return 2 if analyzer.hits else 0


if __name__ == "__main__":
    sys.exit(main())
