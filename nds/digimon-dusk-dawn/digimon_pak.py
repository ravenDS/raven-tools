#!/usr/bin/env python3
"""
Digimon Dusk/Dawn .PAK archive extractor - by ravenDS
https://github.com/RavenDS

Stage 1 (outer PAK):
    u32 file_count
    file_count * { u32 offset; u32 size_with_high_bit_flag }
    raw payload

Stage 2 (inner): every payload begins with an NDS RLE-compression header (compression type 0x30):
    u8  magic = 0x30
    u24 decompressed_size      (little-endian)
    ... RLE token stream ...

Each token starts with a control byte:
    bit 7 = 0 -> next (bits 0..6 + 1) bytes are literals
    bit 7 = 1 -> next byte is repeated (bits 0..6 + 3) times

When decompressed, most entries are standard Nitro graphics files( NCGR, NCLR, NCER, NANR, ...)

Usage:
    python digimon_pak.py ARCHIVE.PAK
"""

import os
import sys
import struct
import pathlib


# Nitro file magics
NITRO_MAGICS = {
    b"RGCN": "NCGR",   # character / tile graphics
    b"RLCN": "NCLR",   # palette
    b"RPCN": "NCPR",   # palette (alt)
    b"RECN": "NCER",   # cell (OAM) data
    b"RNAN": "NANR",   # cell animation
    b"RAMN": "NMAR",   # multi-cell animation
    b"RCSN": "NSCR",   # screen / map
    b"RNCS": "NSCR",   # screen (alt byte order)
    b"RGBN": "NCBR",   # bitmap character
}


def parse_pak(data: bytes):
    """Return list of (offset, size, high_bit_was_set) for a PAK."""
    count = struct.unpack_from("<I", data, 0)[0]
    entries = []
    for i in range(count):
        off, raw = struct.unpack_from("<II", data, 4 + i * 8)
        size = raw & 0x7FFFFFFF
        flag = (raw >> 31) & 1
        entries.append((off, size, flag))
    return entries


def rle_decompress(buf: bytes) -> bytes:
    """NDS BIOS type-0x30 RLE decompression."""
    if len(buf) < 4 or buf[0] != 0x30:
        raise ValueError("not RLE-compressed (expected magic 0x30)")
    dec_size = buf[1] | (buf[2] << 8) | (buf[3] << 16)
    out = bytearray()
    i = 4
    while len(out) < dec_size and i < len(buf):
        flag = buf[i]
        i += 1
        if flag & 0x80:
            count = (flag & 0x7F) + 3
            if i >= len(buf):
                break
            out.extend([buf[i]] * count)
            i += 1
        else:
            count = (flag & 0x7F) + 1
            out.extend(buf[i:i + count])
            i += count
    if len(out) != dec_size:
        # truncated or corrupt; still return what we got
        pass
    return bytes(out[:dec_size])


def classify(decompressed: bytes) -> str:
    """Return a file extension based on the decompressed magic."""
    if len(decompressed) >= 4:
        magic = decompressed[:4]
        if magic in NITRO_MAGICS:
            return NITRO_MAGICS[magic]
    return "bin"


def extract(pak_path: str, out_dir: str):
    data = pathlib.Path(pak_path).read_bytes()
    entries = parse_pak(data)
    os.makedirs(out_dir, exist_ok=True)

    width = max(4, len(str(len(entries) - 1)))
    stats = {"rle": 0, "passthrough": 0, "empty": 0, "by_ext": {}}

    for idx, (off, size, _flag) in enumerate(entries):
        if size == 0:
            stats["empty"] += 1
            continue

        chunk = data[off:off + size]

        if len(chunk) >= 4 and chunk[0] == 0x30:
            try:
                dec = rle_decompress(chunk)
                ext = classify(dec)
                stats["rle"] += 1
            except Exception as e:
                print(f"  [warn] entry {idx}: RLE decompress failed: {e}; writing raw", file=sys.stderr)
                dec = chunk
                ext = "raw"
                stats["passthrough"] += 1
        else:
            # not RLE-wrapped, pass through
            dec = chunk
            ext = "raw"
            stats["passthrough"] += 1

        stats["by_ext"][ext] = stats["by_ext"].get(ext, 0) + 1
        name = f"{idx:0{width}d}.{ext}"
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(dec)

    return stats


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip())
        sys.exit(2)

    pak_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) >= 3 else \
        os.path.splitext(os.path.basename(pak_path))[0]

    print(f"Extracting {pak_path} -> {out_dir}/")
    stats = extract(pak_path, out_dir)
    print(f"  entries decompressed: {stats['rle']}")
    print(f"  passed through (no RLE wrapper): {stats['passthrough']}")
    print(f"  empty entries: {stats['empty']}")
    print(f"  by extension:")
    for ext, n in sorted(stats["by_ext"].items(), key=lambda kv: -kv[1]):
        print(f"    .{ext:<5} {n}")


if __name__ == "__main__":
    main()
