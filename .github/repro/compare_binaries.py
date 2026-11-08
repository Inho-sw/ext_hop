#!/usr/bin/env python3
"""Compare an official HOP binary with a locally rebuilt one, section by section.

Supports ELF (Linux) and PE (Windows). Fields that are expected to vary between
otherwise identical builds are reported separately so real code differences
stand out:

- PE: COFF TimeDateStamp, optional-header CheckSum, debug directory
  (CodeView RSDS GUID/age/timestamp).
- ELF: .note.gnu.build-id (a hash of the other sections, so it only differs
  when something else differs).

Usage: compare_binaries.py <official> <rebuilt>
Exit code 0 when every non-volatile section is byte-identical, 1 otherwise.
"""
import hashlib
import struct
import sys


def read(path):
    with open(path, "rb") as handle:
        return handle.read()


def elf_sections(data):
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("only ELF64 is supported")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        name, kind, _flags, _addr, offset, size = struct.unpack_from("<IIQQQQ", data, base)
        headers.append((name, kind, offset, size))
    str_offset = headers[shstrndx][2]
    sections = {}
    for name, kind, offset, size in headers:
        end = data.index(b"\0", str_offset + name)
        label = data[str_offset + name:end].decode() or "<null>"
        body = b"" if kind == 8 else data[offset:offset + size]  # SHT_NOBITS
        sections[label] = body
    return sections, {}


def pe_sections(data):
    if data[:2] != b"MZ":
        raise ValueError("not a PE file")
    pe, = struct.unpack_from("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = pe + 4
    nsec, timestamp = struct.unpack_from("<HI", data, coff + 2)
    opt_size, = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    checksum, = struct.unpack_from("<I", data, opt + 64)
    debug_rva, debug_size = struct.unpack_from("<II", data, opt + 112 + 6 * 8)
    table = opt + opt_size
    sections = {}
    layout = []
    for index in range(nsec):
        base = table + index * 40
        name = data[base:base + 8].rstrip(b"\0").decode(errors="replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
        sections[name] = bytearray(data[raw_ptr:raw_ptr + raw_size])
        layout.append((name, vaddr, raw_ptr, raw_size))
    volatile = {"coff.TimeDateStamp": timestamp, "opt.CheckSum": checksum}
    mask_pe_debug(data, sections, layout, debug_rva, debug_size, volatile)
    return {k: bytes(v) for k, v in sections.items()}, volatile


def mask_pe_debug(data, sections, layout, debug_rva, debug_size, volatile):
    """Zero debug-directory timestamps and CodeView GUID/age inside section copies."""
    def locate(rva):
        for name, vaddr, raw_ptr, raw_size in layout:
            if vaddr <= rva < vaddr + raw_size:
                return name, rva - vaddr, raw_ptr + (rva - vaddr)
        return None

    if not debug_rva:
        return
    found = locate(debug_rva)
    if not found:
        return
    name, rel, file_off = found
    for entry in range(debug_size // 28):
        e_rel = rel + entry * 28
        e_off = file_off + entry * 28
        stamp, = struct.unpack_from("<I", data, e_off + 4)
        dtype, size, _addr, ptr = struct.unpack_from("<IIII", data, e_off + 12)
        volatile[f"debug[{entry}].TimeDateStamp"] = stamp
        sections[name][e_rel + 4:e_rel + 8] = b"\0" * 4
        if dtype == 2 and data[ptr:ptr + 4] == b"RSDS":  # CodeView
            volatile[f"debug[{entry}].RSDS.guid+age"] = data[ptr + 4:ptr + 24].hex()
            for sec_name, _vaddr, raw_ptr, raw_size in layout:
                if raw_ptr <= ptr < raw_ptr + raw_size:
                    start = ptr - raw_ptr + 4
                    sections[sec_name][start:start + 20] = b"\0" * 20
        elif dtype in (13, 16):  # POGO / REPRO entries embed build-specific hashes
            for sec_name, _vaddr, raw_ptr, raw_size in layout:
                if raw_ptr <= ptr < raw_ptr + raw_size:
                    start = ptr - raw_ptr
                    sections[sec_name][start:start + size] = b"\0" * size


def diff_count(left, right):
    common = min(len(left), len(right))
    differing = sum(1 for a, b in zip(left[:common], right[:common]) if a != b)
    return differing + abs(len(left) - len(right))


def main():
    official_path, rebuilt_path = sys.argv[1], sys.argv[2]
    official, rebuilt = read(official_path), read(rebuilt_path)
    print(f"official sha256 {hashlib.sha256(official).hexdigest()}  {len(official)} B")
    print(f"rebuilt  sha256 {hashlib.sha256(rebuilt).hexdigest()}  {len(rebuilt)} B")
    if official == rebuilt:
        print("RESULT: byte-identical")
        return 0

    parse = pe_sections if official[:2] == b"MZ" else elf_sections
    off_secs, off_vol = parse(official)
    reb_secs, reb_vol = parse(rebuilt)
    for key in sorted(set(off_vol) | set(reb_vol)):
        print(f"volatile {key}: official={off_vol.get(key)} rebuilt={reb_vol.get(key)}")

    ignored = {".note.gnu.build-id"}
    real_diff = False
    print(f"{'section':<24}{'official':>12}{'rebuilt':>12}  status")
    for name in sorted(set(off_secs) | set(reb_secs)):
        left, right = off_secs.get(name), reb_secs.get(name)
        if left is None or right is None:
            status = "MISSING in " + ("official" if left is None else "rebuilt")
            real_diff = True
        elif left == right:
            status = "identical"
        else:
            status = f"DIFF {diff_count(left, right)} bytes"
            if name in ignored:
                status += " (derived, ignored)"
            else:
                real_diff = True
        size_l = len(left) if left is not None else 0
        size_r = len(right) if right is not None else 0
        print(f"{name:<24}{size_l:>12}{size_r:>12}  {status}")
    print("RESULT: " + ("sections differ" if real_diff else "identical except volatile build metadata"))
    return 1 if real_diff else 0


if __name__ == "__main__":
    sys.exit(main())
