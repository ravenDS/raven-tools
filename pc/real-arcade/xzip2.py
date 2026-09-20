#!/usr/bin/env python3
"""
xzip2.py - unpacker for RealArcade "XZip 2.0" archives (2023)

Disassembly work by Chris - https://github.com/christphen
Python implementation by ravenDS - https://github.com/ravenDS

2026: CLI, code rewrite & cleanup + structure layout by Claude

handles:
- .mez   game-info (bare XZip2.0 archive)
- .xtr   catalog / extras (RASGI2.0 signature wrapper + XZip2.0)
- .rgs   secured game installers (RASGI2.0 signature wrapper + XZip2.0)

LAYOUT:
 
overview (all integers little-endian):
    [RASGI2.0 wrapper]    .xtr / .rgs only
    XZip2.0 header        0x4D bytes
    [ID string]
    file table            names, sizes, timestamps
    data chunks           repeated until the last-chunk marker
 
RASGI2.0 wrapper:
    0x00  char[8]     "RASGI2.0"
    0x08  u32         len (counts itself + the signature blob)
    0x0C  u8[]        signature blob, checked by the host installer only
    the XZip2.0 header follows at offset 8 + len
 
XZip2.0 header:
    0x00  char[8]     "XZip2.0\0"
    0x0B  u8          ID string present (only honoured if byte 0x13 == 0)
    0x0D  u8          always 0xFA
    0x11  u8          compressed flag, always 1 (0 is unsupported by the DLL)
    0x12  u8          level 0..8: sets window size and W = level + 7
    0x19  u32         file count (not read by the DLL, file table rules)
    0x25  u32         ID string length
    0x49  u32         CRC32 of bytes 0x00..0x48
    all other header bytes are never read by the DLL
 
ID string:
    id_len bytes, no NUL (game GUID, ...), skipped by the extractor
 
file table:
    u32   usize       decoded size
    u32   crc32       CRC32 of the decoded table
    u32   csize       coded size
    u8    data[csize] splay-tree coded, see splay_decode()
 
    decoded:
        u32   nfiles, ndirs, nnames, nexts
        nfiles records, 22 bytes each:
            u32   mtime       unix timestamp
            u32   size        file size in bytes
            u32   dir_idx     index into the dir strings
            u32   name_idx    index into the name strings
            u32   ext_idx     index into the ext strings
            u8    name_len    copy of the name length
            u8    attributes  win32 flags: 0x01 read-only, 0x02 hidden,
                              0x04 system, 0x10 directory, 0x20 archive
        u8    lengths[ndirs + nnames + nexts]
        strings back to back, no NUL: dirs, then names, then exts
 
    path = dir + name + ("." + ext if ext is not empty)
    dirs carry their own backslashes; a path ending in one is a folder
 
data chunk:
    u8    X           bits used in the last flag byte (0 = all 8),
                      plus 9 if this is the last chunk
    5 blocks, in this order:
        1. flags        one bit per token, LSB first: 1 = literal, 0 = match
        2. literals     one byte per literal
        3. lengths      match length - 4, 0xFF = a u16 (length - 4) follows
        4. offset high  offset bits W .. W+7, one byte per match
        5. offset mid   offset bits W-8 .. W-1, one byte per match
    u32[] extra       low W-8 offset bits of each match, packed MSB-first
                      into u32 words (present only if W > 8)
    u32   crc32       chained CRC32 of the 5 decoded blocks + extra bits,
                      see crc_chain()
 
block:
    u32   usize       decoded size
    u8    coded       1 = range coded (see ari_decode()), 0 = stored
    u32   csize       stored size
    u8    data[csize]
 
match:
    offset = (high << W) | (mid << (W - 8)) | extra
    copy `length` bytes starting (offset + 1) bytes back, overlap allowed
 
all files form one solid LZ stream, cut into files in file-table order by their sizes

format reversed from disassembly of XZipSfx by Chris
(RealArcade RGS loader, export ExtractSFXData, MD5 4391810d090813c09ebafcd9234a6cd0)
addresses refer to that DLL
"""

import argparse
import datetime
import os
import struct
import sys
import zlib

RASGI_MAGIC = b"RASGI2.0"
XZIP_MAGIC = b"XZip2.0\x00"
HEADER_SIZE = 0x4D

# level table at 0x10008208 (stride 0x3E):
# window = w32k * 32 KiB, MIN match = 4, W = offset split bits
LEVELS = {
    0: dict(w32k=1, min_match=4, W=7),
    1: dict(w32k=2, min_match=4, W=8),
    2: dict(w32k=4, min_match=4, W=9),
    3: dict(w32k=8, min_match=4, W=10),
    4: dict(w32k=16, min_match=4, W=11),
    5: dict(w32k=32, min_match=4, W=12),
    6: dict(w32k=64, min_match=4, W=13),
    7: dict(w32k=128, min_match=4, W=14),
    8: dict(w32k=256, min_match=4, W=15),
}


class XZipError(Exception):
    pass


# CRC helpers

def crc_chain(state, data):
    """0x100014d0 inverts result but not input state.
    chained calls are crc32(data, ~state), starting state is 0xFFFFFFFF"""
    return zlib.crc32(data, state ^ 0xFFFFFFFF)


# file-table coder
# - splay-tree prefix code (D. W. Jones 1988)
# - one tree per previous byte (0x10001e78 / 0x10001ebe / 0x10001f54 / 0x10001fd7)

def _new_tree():
    left = [2 * k for k in range(0x104)]
    right = [2 * k + 1 for k in range(0x104)]
    up = [i >> 1 for i in range(0x208)]
    return left, right, up


def _splay(left, right, up, sym):
    a = sym + 0x100
    while True:
        c = up[a]
        if c == 1:
            return
        d = up[c]
        b = right[d]
        if c == b:
            b = left[d]
            left[d] = a
        else:
            right[d] = a
        if a == left[c]:
            left[c] = b
        else:
            right[c] = b
        up[b] = c
        up[a] = d
        a = d
        if a == 1:
            return


def splay_decode(src, usize):
    trees = {}
    buf = bytes(src) + b"\0" * 8
    out = bytearray()
    remaining = usize
    left, right, up = trees.setdefault(0, _new_tree())
    node = 1
    off = 0
    limit = len(src) + 5
    while off < limit and remaining > 0:
        word = int.from_bytes(buf[off:off + 4], "little")
        for bit in range(31, -1, -1):
            node = right[node] if (word >> bit) & 1 else left[node]
            if node >= 0x100:
                if remaining <= 0:
                    break
                remaining -= 1
                sym = node & 0xFF
                out.append(sym)
                _splay(left, right, up, sym)
                t = trees.get(sym)
                if t is None:
                    t = trees[sym] = _new_tree()
                left, right, up = t
                node = 1
        off += 4
    return bytes(out)


# stream coder: adaptive frequency range decoder (0x1000122f)
# two-level byte model (0x10001360)
# all models reset for every block

# (symbols, increment) for 12 models, model 0 is top-level selector
_MODEL_PARAMS = [(16, 12), (2, 4), (4, 4), (8, 4), (32, 4), (32, 3),
                 (32, 3), (32, 3), (32, 3), (32, 2), (32, 2), (32, 2)]
# top symbol s -> group s-1: literal byte, or (sub-model, base value)
_GROUPS = [("lit", 0), ("lit", 1), ("sub", 1, 2), ("sub", 2, 4),
           ("sub", 3, 8), ("sub", 4, 16), ("sub", 5, 48), ("sub", 6, 64),
           ("sub", 7, 96), ("sub", 8, 128), ("sub", 9, 160),
           ("sub", 10, 192), ("sub", 11, 224), ("lit", 255)]
_MAX_TOTAL = 1000


def ari_decode(data, count):
    freqs = [[0] + [inc] * n + [0] for n, inc in _MODEL_PARAMS]
    totals = [inc * n for n, inc in _MODEL_PARAMS]
    incs = [inc for _, inc in _MODEL_PARAMS]
    sizes = [n for n, _ in _MODEL_PARAMS]

    src = bytes(data) + b"\0" * 16
    # bit reader
    # MSB-first
    # priming loop shift mask before first test, so bit 7 of byte 0 is never read
    bitbuf = src[0] & 0x7F
    nbits = 7
    pos = 1

    code = 0
    need = 25
    while nbits < need:
        bitbuf = (bitbuf << 8) | src[pos]
        pos += 1
        nbits += 8
    nbits -= need
    code = bitbuf >> nbits
    bitbuf &= (1 << nbits) - 1
    rng = 0x2000000

    out = bytearray(count)

    def decode(m):
        nonlocal rng, code, bitbuf, nbits, pos
        total = totals[m]
        r = rng // total
        if r == 0:
            raise XZipError("range decoder underflow (corrupt block)")
        t = code // r
        if t >= total:
            t = total - 1
        freq = freqs[m]
        sym = 0
        cum = 0
        while cum <= t:
            sym += 1
            cum += freq[sym]
        f = freq[sym]
        low = cum - f
        code = (code - low * r) & 0xFFFFFFFF
        if cum < total:
            rng = f * r
        else:
            rng = (rng - low * r) & 0xFFFFFFFF
        if rng <= 0x1000000:
            k = 0
            while (rng << k) <= 0x1000000:
                k += 1
            rng <<= k
            while nbits < k:
                bitbuf = (bitbuf << 8) | src[pos]
                pos += 1
                nbits += 8
            nbits -= k
            code = ((code << k) | (bitbuf >> nbits)) & 0xFFFFFFFF
            bitbuf &= (1 << nbits) - 1
        freq[sym] += incs[m]
        total += incs[m]
        if total > _MAX_TOTAL:
            total = 0
            for i in range(1, sizes[m] + 1):
                v = (freq[i] + 1) >> 1
                freq[i] = v
                total += v
        totals[m] = total
        return sym

    try:
        for i in range(count):
            s = decode(0)
            if s > len(_GROUPS):
                raise XZipError("invalid top-level symbol %d (corrupt block)" % s)
            g = _GROUPS[s - 1]
            if g[0] == "lit":
                out[i] = g[1]
            else:
                out[i] = (g[2] + decode(g[1]) - 1) & 0xFF
    except IndexError:
        raise XZipError("range decoder ran past end of block (corrupt block)")
    return bytes(out)


# container

class Reader:
    def __init__(self, buf, pos=0):
        self.buf = buf
        self.pos = pos

    def read(self, n):
        v = self.buf[self.pos:self.pos + n]
        if len(v) != n:
            raise XZipError("unexpected end of file at 0x%X" % self.pos)
        self.pos += n
        return v

    def u8(self):
        return self.read(1)[0]

    def u32(self):
        return struct.unpack("<I", self.read(4))[0]


class Entry:
    __slots__ = ("time", "size", "dir", "name", "ext", "attrs", "path")

    def __init__(self, time, size, d, name, ext, attrs, path):
        self.time, self.size, self.dir = time, size, d
        self.name, self.ext, self.attrs, self.path = name, ext, attrs, path

    def attr_str(self):
        a = self.attrs
        return "".join(c if a & bit else "-" for bit, c in
                       ((0x10, "D"), (0x20, "A"), (0x01, "R"), (0x02, "H"),
                        (0x04, "S")))

    @property
    def is_dir(self):
        return self.path.endswith("\\")


class Archive:
    def __init__(self, data, label="<archive>"):
        self.data = data
        self.label = label
        self.wrapper = None
        self.base = self._locate()
        self._parse_header()
        self._parse_file_table()

    # locating
    def _locate(self):
        d = self.data
        if d.startswith(XZIP_MAGIC):
            return 0
        if d.startswith(RASGI_MAGIC) and len(d) >= 12:
            (ln,) = struct.unpack_from("<I", d, 8)
            base = 8 + ln
            if d[base:base + 8] == XZIP_MAGIC:
                self.wrapper = ("RASGI2.0", d[12:base])
                return base
        idx = d.find(XZIP_MAGIC)
        if idx < 0:
            raise XZipError("no XZip2.0 archive found")
        self.wrapper = ("unknown", d[:idx])
        return idx

    # header
    def _parse_header(self):
        rd = Reader(self.data, self.base)
        hdr = rd.read(HEADER_SIZE)
        self.header = hdr
        if hdr[0x0D] != 0xFA:
            raise XZipError("bad header (byte 0x0D = 0x%02X, expected 0xFA)"
                            % hdr[0x0D])
        (stored,) = struct.unpack_from("<I", hdr, 0x49)
        if zlib.crc32(hdr[:0x49]) != stored:
            raise XZipError("header CRC mismatch")
        self.compressed = hdr[0x11]
        self.level = hdr[0x12]
        (self.file_count,) = struct.unpack_from("<I", hdr, 0x19)
        (id_len,) = struct.unpack_from("<I", hdr, 0x25)
        self.id = b""
        if hdr[0x0B] and hdr[0x13] == 0:
            self.id = rd.read(id_len)
        if not self.compressed:
            raise XZipError("uncompressed (byte 0x11 = 0) archives are not "
                            "supported yet - please share a sample")
        if self.level not in LEVELS:
            raise XZipError("unknown compression level %d" % self.level)
        self.params = LEVELS[self.level]
        self._rd = rd

    # file table
    def _parse_file_table(self):
        rd = self._rd
        usize = rd.u32()
        crc = rd.u32()
        csize = rd.u32()
        tab = splay_decode(rd.read(csize), usize)
        if len(tab) != usize or zlib.crc32(tab) != crc:
            raise XZipError("file table CRC mismatch")
        nfiles, ndirs, nnames, nexts = struct.unpack_from("<4I", tab, 0)
        p = 16
        recs = []
        for _ in range(nfiles):
            recs.append(struct.unpack_from("<5I2B", tab, p))
            p += 22
        lens = tab[p:p + ndirs + nnames + nexts]
        p += ndirs + nnames + nexts
        strings = []
        for ln in lens:
            strings.append(tab[p:p + ln].decode("latin-1"))
            p += ln
        dirs = strings[:ndirs]
        names = strings[ndirs:ndirs + nnames]
        exts = strings[ndirs + nnames:]
        self.entries = []
        for t, size, di, ni, ei, _name_len, attrs in recs:
            d, n, e = dirs[di], names[ni], exts[ei]
            path = d + n + ("." + e if e else "")  # 0x10002469
            self.entries.append(Entry(t, size, d, n, e, attrs, path))
        if nfiles != self.file_count:
            print("warning: %s: header says %d files, table has %d"
                  % (self.label, self.file_count, nfiles), file=sys.stderr)
        self.data_offset = rd.pos

    # data
    def _read_chunk(self, rd):
        W = self.params["W"]
        X = rd.u8()
        crc = 0xFFFFFFFF
        streams = []
        for _ in range(5):
            usize = rd.u32()
            coded = rd.u8()
            csize = rd.u32()
            raw = rd.read(csize)
            dec = ari_decode(raw, usize) if coded else bytes(raw)
            crc = crc_chain(crc, dec)
            streams.append(dec)
        count = len(streams[3])
        extra = [0] * count
        if W > 8:
            nb = W - 8
            bitbuf = rd.u32()
            bitcnt = 32
            for i in range(count):
                if bitcnt >= nb:  # 0x100031a8
                    rem = bitcnt - nb
                    extra[i] = (bitbuf >> rem) & 0xFFFF
                    if rem == 0 and i < count - 1:
                        bitbuf = rd.u32()
                        bitcnt = 32
                    else:
                        bitbuf &= (1 << rem) - 1
                        bitcnt = rem
                else:  # 0x10003214
                    v = bitbuf & 0xFFFF
                    bitbuf = rd.u32()
                    v = ((v << (nb - bitcnt)) & 0xFFFF) | (bitbuf >> (bitcnt - nb + 32))
                    extra[i] = v & 0xFFFF
                    bitcnt += 32 - nb
                    bitbuf &= (1 << bitcnt) - 1
            crc = crc_chain(crc, struct.pack("<%dH" % count, *extra))
        if rd.u32() != crc:
            raise XZipError("data chunk CRC mismatch at 0x%X" % rd.pos)
        return X, streams, extra

    def _lz(self, out, X, streams, extra):
        """0x10001c6b: flag bit 1 = literal, 0 = match, LSB first"""
        W = self.params["W"]
        mn = self.params["min_match"]
        A, B, C, D, E = streams
        sh_e = (W - 8) & 31  # x86 masks shift counts
        bi = ci = di = 0
        last = X > 8
        if last:
            X -= 9
        nA = len(A)
        try:
            for i in range(nA):
                flags = A[i]
                nbits = X if (i == nA - 1 and X) else 8
                for _ in range(nbits):
                    if flags & 1:
                        out.append(B[bi])
                        bi += 1
                    else:
                        off = ((D[di] << W) | (E[di] << sh_e)
                               | (extra[di] & 0xFF)) & 0xFFFFFFFF
                        di += 1
                        ln = C[ci]
                        ci += 1
                        if ln == 0xFF:
                            ln = C[ci] | (C[ci + 1] << 8)
                            ci += 2
                        ln += mn
                        dist = off + mn - 3  
                        # src = pos - MIN - off + 3
                        src = len(out) - dist
                        if src < 0:  # window starts zero-filled
                            pre = min(-src, ln)
                            out.extend(b"\0" * pre)
                            ln -= pre
                            src += pre
                        if dist >= ln:
                            out += out[src:src + ln]
                        else:
                            for k in range(ln):
                                out.append(out[src + k])
                    flags >>= 1
        except IndexError:
            raise XZipError("LZ stream underrun (corrupt chunk)")
        if (bi, ci, di) != (len(B), len(C), len(D)):
            print("warning: %s: chunk streams not fully consumed" % self.label,
                  file=sys.stderr)
        return last

    def decompress(self):
        """return solid output stream (all files concatenated)"""
        total = sum(e.size for e in self.entries)
        rd = Reader(self.data, self.data_offset)
        out = bytearray()
        chunks = 0
        while rd.pos < len(self.data):
            X, streams, extra = self._read_chunk(rd)
            chunks += 1
            if self._lz(out, X, streams, extra):
                break
        if len(out) != total:
            raise XZipError("decoded %d bytes, file table expects %d"
                            % (len(out), total))
        self.chunks = chunks
        self.trailing = len(self.data) - rd.pos
        return bytes(out)

    def files(self):
        """(entry, bytes) in archive order"""
        blob = self.decompress()
        p = 0
        for e in self.entries:
            yield e, blob[p:p + e.size]
            p += e.size


# CLI

def safe_join(root, arc_path):
    parts = [p for p in arc_path.replace("\\", "/").split("/")
             if p not in ("", ".", "..")]
    if parts and len(parts[0]) == 2 and parts[0][1] == ":":
        parts = parts[1:]  # drop drive letters
    return os.path.join(root, *parts) if parts else root


def fmt_time(t):
    if not t:
        return "-" * 19
    try:
        return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "0x%08X" % t


def describe(arc):
    w = arc.wrapper[0] if arc.wrapper else "none"
    print("%s: XZip2.0 @ 0x%X, wrapper %s, level %d, %d file(s), ID %r"
          % (arc.label, arc.base, w, arc.level, len(arc.entries),
             arc.id.decode("latin-1")))


def cmd_list(arc, verbose):
    describe(arc)
    total = 0
    for e in arc.entries:
        total += e.size
        attrs = "  " + e.attr_str() if verbose else ""
        print("  %10d  %s%s  %s" % (e.size, fmt_time(e.time), attrs, e.path))
    print("  %10d  total" % total)


def cmd_extract(arc, outroot, test_only, quiet):
    if not quiet:
        describe(arc)
    count = 0
    written = {}
    for e, blob in arc.files():
        count += 1
        if test_only:
            continue
        dest = safe_join(outroot, e.path)
        if e.is_dir:
            os.makedirs(dest, exist_ok=True)
            continue
        key = os.path.normcase(dest)
        if key in written:
            if written[key] == blob:
                continue  # packager stored same file twice
            stem, ext = os.path.splitext(dest)
            n = 2
            while os.path.normcase("%s~%d%s" % (stem, n, ext)) in written:
                n += 1
            dest = "%s~%d%s" % (stem, n, ext)
            key = os.path.normcase(dest)
            print("warning: duplicate path %s, saved as %s" % (e.path, dest),
                  file=sys.stderr)
        written[key] = blob
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(blob)
        if e.time:
            try:
                os.utime(dest, (e.time, e.time))
            except (OverflowError, OSError, ValueError):
                pass
        if not quiet:
            print("  %s (%d bytes)" % (dest, len(blob)))
    if not quiet:
        tail = ", %d trailing bytes" % arc.trailing if arc.trailing else ""
        print("  OK: %d file(s), %d chunk(s), all CRCs verified%s"
              % (count, arc.chunks, tail))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="xzip2.py - Unpack RealArcade XZip 2.0 archives (.mez/.xtr/.rgs)")
    ap.add_argument("archives", nargs="+",
                    help="one or more .mez / .xtr / .rgs files")
    ap.add_argument("-l", "--list", action="store_true",
                    help="list contents only")
    ap.add_argument("-t", "--test", action="store_true",
                    help="decode and verify CRCs without writing")
    ap.add_argument("-o", "--outdir", default=None,
                    help="custom output folder")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="with -l, also show file attributes")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="only print errors when extracting or testing")
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        ap.print_help()
        return 0
    args = ap.parse_args(argv)

    failed = 0
    for path in args.archives:
        try:
            with open(path, "rb") as fh:
                arc = Archive(fh.read(), label=path)
            if args.list:
                cmd_list(arc, args.verbose)
            else:
                stem = os.path.splitext(os.path.basename(path))[0]
                root = args.outdir
                if root is None:
                    root = os.path.dirname(os.path.abspath(path))
                cmd_extract(arc, os.path.join(root, stem),
                            args.test, args.quiet)
        except BrokenPipeError:
            raise
        except (XZipError, OSError) as exc:
            failed += 1
            print("error: %s: %s" % (path, exc), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
