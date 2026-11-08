"""Application-layer extractors: DNS, TLS ClientHello SNI, plaintext HTTP, canary needles."""
import base64
import ipaddress
import struct


def parse_dns(payload):
    """Return (queries, answers) where answers is a list of (name, ip)."""
    if len(payload) < 12:
        return [], []
    _tid, _flags, qd, an = struct.unpack("!HHHH", payload[:8])
    pos, queries, answers = 12, [], []
    try:
        for _ in range(qd):
            name, pos = _dns_name(payload, pos)
            pos += 4
            queries.append(name)
        for _ in range(an):
            name, pos = _dns_name(payload, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", payload[pos:pos + 10])
            pos += 10
            rdata = payload[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1 and rdlen == 4:
                answers.append((name, ".".join(str(b) for b in rdata)))
            elif rtype == 28 and rdlen == 16:
                answers.append((name, str(ipaddress.IPv6Address(rdata))))
    except (IndexError, struct.error, ValueError):
        pass
    return queries, answers


def _dns_name(buf, pos, depth=0):
    labels = []
    while True:
        length = buf[pos]
        if length == 0:
            return ".".join(labels), pos + 1
        if length & 0xC0 == 0xC0:
            if depth > 10:
                raise ValueError("dns pointer loop")
            ptr = struct.unpack("!H", buf[pos:pos + 2])[0] & 0x3FFF
            name, _ = _dns_name(buf, ptr, depth + 1)
            labels.append(name)
            return ".".join(labels), pos + 2
        labels.append(buf[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length


def parse_sni(payload):
    """Return the SNI host name from a TLS ClientHello record, or None."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 9 + 2 + 32  # record(5) + handshake header(4) + version + random
        pos += 1 + payload[pos]  # session id
        pos += 2 + struct.unpack("!H", payload[pos:pos + 2])[0]  # cipher suites
        pos += 1 + payload[pos]  # compression methods
        end = pos + 2 + struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            if ext_type == 0:
                name_len = struct.unpack("!H", payload[pos + 7:pos + 9])[0]
                return payload[pos + 9:pos + 9 + name_len].decode("ascii", "replace")
            pos += 4 + ext_len
    except (IndexError, struct.error):
        return None
    return None


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ", b"CONNECT ")


def parse_http_request(payload):
    """Return 'METHOD target (Host: x)' for a plaintext HTTP request start, or None."""
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
    host = next((line.split(":", 1)[1].strip() for line in head[1:] if line.lower().startswith("host:")), "")
    return f"{head[0][:200]} (Host: {host})"


def canary_needles(token):
    """Encodings of the canary token to search for: raw, UTF-16, Base64 (3 alignments), hex."""
    raw = token.encode("utf-8")
    needles = {
        "ascii": raw,
        "utf-16le": token.encode("utf-16-le"),
        "utf-16be": token.encode("utf-16-be"),
        "hex": raw.hex().encode(),
        "HEX": raw.hex().upper().encode(),
    }
    for shift in range(3):
        encoded = base64.b64encode(b"\0" * shift + raw)
        core = encoded[4:-4]  # drop chars that depend on neighbouring bytes
        needles[f"base64+{shift}"] = core
        needles[f"base64url+{shift}"] = core.replace(b"+", b"-").replace(b"/", b"_")
        utf16 = base64.b64encode(b"\0" * shift + token.encode("utf-16-le"))[4:-4]
        needles[f"base64(utf-16le)+{shift}"] = utf16
    return needles
