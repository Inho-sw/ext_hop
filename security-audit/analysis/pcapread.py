"""Minimal pcap/pcapng reader and Ethernet/IP/TCP/UDP decoder (Python stdlib only)."""
import ipaddress
import struct

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229


def read_packets(path):
    """Yield (timestamp_seconds, linktype, frame_bytes) from a pcap or pcapng file."""
    with open(path, "rb") as handle:
        head = handle.read(4)
        handle.seek(0)
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(handle)
        elif head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _read_pcap(handle)
        else:
            raise ValueError(f"unknown capture format: {path}")


def _read_pcap(handle):
    header = handle.read(24)
    magic = header[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
    divisor = 1e9 if nano else 1e6
    while True:
        rec = handle.read(16)
        if len(rec) < 16:
            return
        sec, frac, caplen, _orig = struct.unpack(endian + "IIII", rec)
        data = handle.read(caplen)
        if len(data) < caplen:
            return
        yield sec + frac / divisor, linktype, data


def _read_pcapng(handle):
    endian = "<"
    interfaces = []  # list of (linktype, ts_divisor)
    while True:
        head = handle.read(8)
        if len(head) < 8:
            return
        block_type = struct.unpack("<I", head[:4])[0]
        if block_type == 0x0A0D0D0A:
            bom = handle.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            length = struct.unpack(endian + "I", head[4:8])[0]
            handle.read(length - 12)
            interfaces = []
            continue
        block_type, length = struct.unpack(endian + "II", head)
        if length < 12:
            raise ValueError("corrupt pcapng block length")
        body = handle.read(length - 12)
        handle.read(4)  # trailing length
        if block_type == 1:
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _if_tsresol(body[8:], endian)))
        elif block_type == 6:
            iface, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
            linktype, divisor = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e6)
            yield ((ts_hi << 32) | ts_lo) / divisor, linktype, body[20:20 + caplen]
        elif block_type == 3:
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            orig = struct.unpack(endian + "I", body[:4])[0]
            yield 0.0, linktype, body[4:4 + orig]
        elif block_type == 2:
            iface, _drops, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "HHIIII", body[:20])
            linktype, divisor = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e6)
            yield ((ts_hi << 32) | ts_lo) / divisor, linktype, body[20:20 + caplen]


def _if_tsresol(options, endian):
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos:pos + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = options[pos + 4]
            return float(2 ** (value & 0x7F)) if value & 0x80 else float(10 ** value)
        pos += 4 + ((length + 3) & ~3)
    return 1e6


def decode(linktype, frame):
    """Return a dict describing the packet, or None if it is not IP/TCP/UDP."""
    src_mac = dst_mac = None
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        dst_mac, src_mac = frame[0:6].hex("-").upper(), frame[6:12].hex("-").upper()
        ethertype, offset = struct.unpack("!H", frame[12:14])[0], 14
        while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
            ethertype, offset = struct.unpack("!H", frame[offset + 2:offset + 4])[0], offset + 4
        ip = frame[offset:]
        if ethertype not in (0x0800, 0x86DD):
            return None
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        ip = frame
    else:
        return None
    pkt = _decode_ip(ip)
    if pkt:
        pkt["src_mac"], pkt["dst_mac"] = src_mac, dst_mac
    return pkt


def _decode_ip(ip):
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4 and len(ip) >= 20:
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0] or len(ip)
        frag = struct.unpack("!H", ip[6:8])[0] & 0x1FFF
        proto = ip[9]
        src, dst = ipaddress.ip_address(ip[12:16]), ipaddress.ip_address(ip[16:20])
        l4 = ip[ihl:total] if frag == 0 else b""
    elif version == 6 and len(ip) >= 40:
        proto = ip[6]
        src, dst = ipaddress.ip_address(ip[8:24]), ipaddress.ip_address(ip[24:40])
        l4 = ip[40:40 + struct.unpack("!H", ip[4:6])[0]]
    else:
        return None
    pkt = {"ip_bytes": ip, "src": str(src), "dst": str(dst), "proto": proto,
           "sport": None, "dport": None, "payload": b"", "tcp_flags": 0}
    if proto == 6 and len(l4) >= 20:
        pkt["sport"], pkt["dport"] = struct.unpack("!HH", l4[:4])
        data_off = (l4[12] >> 4) * 4
        pkt["tcp_flags"] = l4[13]
        pkt["payload"] = l4[data_off:]
    elif proto == 17 and len(l4) >= 8:
        pkt["sport"], pkt["dport"] = struct.unpack("!HH", l4[:4])
        pkt["payload"] = l4[8:]
    return pkt
