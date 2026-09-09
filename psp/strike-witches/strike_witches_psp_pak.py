#!/usr/bin/env python3
"""
strike_witches_psp_pak.py - https://github.com/ravenDS/raven-tools

Extractor for Strike Witches: Silver Wings (PSP) .pak archives

Layout:
  0x00 u32 BE : decompressed size
  0x04 ...    : zlib stream (deflate, 0x78 0xDA)

Decompressed layout:
  0x00            u32 LE : entry count n
  0x04            n * u32 LE : entry offsets (into decompressed data)
  0x04 + 4*N      n * u32 LE : entry sizes
first entry starts right after the table

Entry types (based on magic):
  MIG.00.1PSP  -> .gim  (PSP GIM texture)
  OMG.00.1PSP  -> .gmo  (PSP GMO model)
  RIFF....WAVE -> .wav
  VAGp         -> .vag  (PS ADPCM, name pulled from header)
More can be added

Usage:
  python3 strike_witches_psp_pak.py archive.pak [-o outdir]
"""

import argparse
import struct
import sys
import zlib
from pathlib import Path

MAGIC_EXT = [
    (b"MIG.00.1PSP\x00", ".gim"),
    (b"OMG.00.1PSP\x00", ".gmo"),
    (b"VAGp", ".vag"),
]


def guess_ext(data: bytes) -> str:
    for magic, ext in MAGIC_EXT:
        if data.startswith(magic):
            return ext
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return ".wav"
    return ".bin"


def vag_name(data: bytes) -> str | None:
    """VAGp header stores ASCII name at 0x20 (16 bytes)"""
    if not data.startswith(b"VAGp") or len(data) < 0x30:
        return None
    raw = data[0x20:0x30].split(b"\x00", 1)[0]
    name = raw.decode("ascii", errors="ignore").strip()
    # keep it filesystem-safe
    name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return name or None


def decompress_pak(raw: bytes) -> bytes:
    if len(raw) < 6:
        raise ValueError("file too small to be a .pak")
    declared = struct.unpack(">I", raw[:4])[0]
    dec = zlib.decompress(raw[4:])
    if len(dec) != declared:
        print(
            f"warning: declared size {declared:#x} != actual {len(dec):#x}",
            file=sys.stderr,
        )
    return dec


def parse_table(dec: bytes):
    (count,) = struct.unpack_from("<I", dec, 0)
    table_end = 4 + 8 * count
    if count == 0 or table_end > len(dec):
        raise ValueError(f"bad entry count {count}")
    offsets = struct.unpack_from(f"<{count}I", dec, 4)
    sizes = struct.unpack_from(f"<{count}I", dec, 4 + 4 * count)
    # first entry should start at or after end of table
    if offsets[0] < table_end:
        raise ValueError(
            f"first offset {offsets[0]:#x} overlaps table (ends @ {table_end:#x})"
        )
    return list(zip(offsets, sizes))


def extract(pak_path: Path, out_dir: Path) -> None:
    raw = pak_path.read_bytes()
    dec = decompress_pak(raw)
    entries = parse_table(dec)

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = pak_path.stem
    used_names: set[str] = set()

    print(f"{pak_path.name}: {len(entries)} entries, {len(dec):#x} bytes decompressed")
    for i, (off, size) in enumerate(entries):
        if off + size > len(dec):
            print(f"  [{i:03d}] off={off:#x} size={size:#x} out of range, skipped",
                  file=sys.stderr)
            continue
        data = dec[off : off + size]
        ext = guess_ext(data)

        base = f"{stem}_{i:03d}"
        if ext == ".vag":
            n = vag_name(data)
            if n:
                base = f"{stem}_{i:03d}_{n}"
        name = base + ext
        # avoid collisions from duplicate names
        k = 1
        while name in used_names:
            name = f"{base}~{k}{ext}"
            k += 1
        used_names.add(name)

        (out_dir / name).write_bytes(data)
        print(f"  [{i:03d}] off={off:#08x} size={size:#08x} -> {name}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("pak", nargs="+", type=Path, help=".pak file to extract")
    ap.add_argument("-o", "--out", type=Path, default=None,
                    help="output directory (default: <pakname>_out next to input)")
    args = ap.parse_args()

    for pak in args.pak:
        out = args.out if args.out else pak.with_name(pak.stem + "_out")
        extract(pak, out)


if __name__ == "__main__":
    main()
