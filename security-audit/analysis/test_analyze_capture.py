"""Synthetic end-to-end tests for analyze_capture.py (run: python -m unittest test_analyze_capture)."""
import base64
import pathlib
import struct
import tempfile
import unittest

import analyze_capture

VM_MAC = bytes.fromhex("00155d010203")
GW_MAC = bytes.fromhex("00155d0000aa")
VM_IP, GW_IP = bytes([172, 20, 0, 10]), bytes([172, 20, 0, 1])
REMOTE_IP = bytes([140, 82, 112, 3])
TOKEN = "HOPCANARY-0123abcd-89ef4567"


def ipv4(src, dst, proto, l4):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, src, dst)
    return header + l4


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, payload, flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 65535, 0, 0) + payload


def ether(src_mac, dst_mac, ip):
    return dst_mac + src_mac + b"\x08\x00" + ip


def dns_query(name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q


def dns_answer(name, ip):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip
    return struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q + answer


def client_hello(host):
    name = host.encode()
    sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\0" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack("!H", len(sni)) + sni
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def write_pcapng(path, frames):
    def block(btype, body):
        pad = body + b"\0" * ((4 - len(body) % 4) % 4)
        length = 12 + len(pad)
        return struct.pack("<II", btype, length) + pad + struct.pack("<I", length)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 0))
    for i, frame in enumerate(frames):
        ts = int((1_700_000_000 + i * 0.001) * 1e6)  # pktmon 중복은 수 μs 간격
        out += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    pathlib.Path(path).write_bytes(out)


def write_pcap(path, frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_100 + i, 0, len(frame), len(frame)) + frame
    pathlib.Path(path).write_bytes(out)


class AnalyzerTest(unittest.TestCase):
    def run_analyzer(self, frames, writer=write_pcapng, token=TOKEN, wfp=None):
        with tempfile.TemporaryDirectory() as tmp:
            cap = pathlib.Path(tmp, "c.pcapng")
            writer(cap, frames)
            args = [str(cap), "--vm-mac", "00-15-5D-01-02-03", "--out", str(pathlib.Path(tmp, "r.md"))]
            if token:
                args += ["--canary", token]
            if wfp:
                pathlib.Path(tmp, "w.csv").write_text(wfp, encoding="utf-8-sig")
                args += ["--wfp-csv", str(pathlib.Path(tmp, "w.csv"))]
            code = analyze_capture.main(args)
            return code, pathlib.Path(tmp, "r.md").read_text(encoding="utf-8")

    def base_frames(self):
        out = lambda l4, proto, dst=REMOTE_IP: ether(VM_MAC, GW_MAC, ipv4(VM_IP, dst, proto, l4))
        back = lambda l4, proto, src=REMOTE_IP: ether(GW_MAC, VM_MAC, ipv4(src, VM_IP, proto, l4))
        hello = out(tcp(50000, 443, client_hello("github.com")), 6)
        return [
            out(udp(53000, 53, dns_query("github.com")), 17, GW_IP),
            back(udp(53, 53000, dns_answer("github.com", REMOTE_IP)), 17, GW_IP),
            hello, hello,  # pktmon duplicate
            back(tcp(443, 50000, b"\x17\x03\x03\x00\x10" + b"x" * 16), 6),
        ]

    def test_clean_capture(self):
        wfp = "Time,Pid,Application,Direction,Protocol,SourceAddress,SourcePort,DestAddress,DestPort\n" \
              "t,1,\\device\\harddiskvolume3\\program files\\hop\\hop-desktop.exe,Outbound,6,172.20.0.10,50000,140.82.112.3,443\n"
        code, report = self.run_analyzer(self.base_frames(), wfp=wfp)
        self.assertEqual(code, 0)
        self.assertIn("**발견되지 않음**", report)
        self.assertIn("- github.com (1)", report)
        self.assertIn("중복 1", report)
        self.assertIn("| 140.82.112.3 | github.com | 443 |", report)
        self.assertIn("hop-desktop.exe", report.split("## 전체 원격 주소")[0])

    def test_base64_canary_split_across_packets(self):
        body = b"doc=" + base64.b64encode(b"xx" + TOKEN.encode() + b"yy")
        req = b"POST /up HTTP/1.1\r\nHost: evil.example\r\n\r\n" + body
        frames = self.base_frames() + [
            ether(VM_MAC, GW_MAC, ipv4(VM_IP, REMOTE_IP, 6, tcp(50001, 80, req[:60]))),
            ether(VM_MAC, GW_MAC, ipv4(VM_IP, REMOTE_IP, 6, tcp(50001, 80, req[60:]))),
        ]
        code, report = self.run_analyzer(frames, writer=write_pcap)
        self.assertEqual(code, 2)
        self.assertIn("**발견", report)
        self.assertIn("base64+2", report)
        self.assertIn("POST /up HTTP/1.1 (Host: evil.example)", report)

    def test_utf16_canary_counted_once(self):
        payload = b"A" * 10 + TOKEN.encode("utf-16-le")
        frames = [ether(VM_MAC, GW_MAC, ipv4(VM_IP, REMOTE_IP, 17, udp(40000, 9999, payload))),
                  ether(VM_MAC, GW_MAC, ipv4(VM_IP, REMOTE_IP, 17, udp(40000, 9999, b"tail-only")))]
        code, report = self.run_analyzer(frames)
        self.assertEqual(code, 2)
        self.assertEqual(report.count("| utf-16le |"), 1)


if __name__ == "__main__":
    unittest.main()
