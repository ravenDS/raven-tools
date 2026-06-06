#!/usr/bin/env python3
"""
croket_bg_conv.py — Convert NDS Croket! (xx)_LZ.bin files (in BG folder) to BMP or PNG (must be decompressed first!)
by ravenDS - github.com/ravenDS

Usage:
    python croket_bg_conv.py <input.bin> [output.bmp]
    python croket_bg_conv.py <input.bin> --scale 3
    python croket_bg_conv.py <input.bin> --alpha          # exports RGBA PNG
    python croket_bg_conv.py <input.bin> --alpha out.png  # explicit output path

If no output path is given, the file is saved alongside the input
Default format is BMP, with --alpha the default extension becomes .png and has transparency

File format (little-endian):
  Main header (0x20 bytes):
    0x00  u32  header_size      Always 0x20
    0x04  u32  map_offset       Byte offset to the tilemap section header
    0x08  u32  pal_offset       Offset to the embedded 16-color BGR555 palette
    0x0C  u16  num_tiles        Number of 8x8 tiles (1-indexed; tile 1 = blank)
    0x0E  u16  flag_0E          Unknown (observed: 1)
    0x10  u16  flag_10          Unknown (observed: 8)
    0x12  u16  flag_12          Unknown (observed: 1)
    0x14  u32  palette_size     Palette data size in bytes
    0x18+ u32  (zero padding)

  Tile data  [0x20 .. map_offset]:
    num_tiles x 32 bytes of 4bpp 8x8 tile graphics.
    Each byte: low nibble = left pixel, high nibble = right pixel.
    Palette indices used: 0 = transparent/bg, 1 = glyph fill, 2 = glyph outline.

  Tilemap section header (0x10 bytes at map_offset):
    0x00  u32  (mirrors main header_size)
    0x04  u32  map_height_tiles   Number of tile rows (e.g. 24 -> 192 px)
    0x08  u32  (0)
    0x0C  u32  (0)

  Tilemap data  [map_offset+0x10 .. pal_offset]:
    u16 screen-entry values, 32 entries wide (NDS BG tilemap format):
      bits  9-0  : tile index (0 or 1 = blank)
      bit    10  : horizontal flip
      bit    11  : vertical flip
      bits 15-12 : extended palette slot

  Embedded palette  [pal_offset .. pal_offset+32]:
    32 bytes = 16 BGR555 colors x 2 bytes each.
    Color 0 (typically 0x7FFF = white) is the NDS transparency sentinel,
    rendered as black background.
    An external --palette file always overrides the embedded palette.
"""

import struct
import sys
import os
import zlib
import argparse
from pathlib import Path


# Default palette: white glyphs + dark outline on black background
#   index 0 -> black background
#   index 1 -> white fill
#   index 2 -> dark outline
DEFAULT_PALETTE = {
    0: (0,   0,   0),
    1: (255, 255, 255),
    2: (40,  40,  40),
}

NDS_MAP_WIDTH_TILES = 32   # NDS tiled BG is always 32 tiles (256 px) wide


# BMP writer (24-bit RGB, written by Claude! not from me)

def write_bmp(path, width, height, pixels):
    """
    Write a 24-bit uncompressed BMP file.

    pixels  : flat list of (R, G, B) tuples, row-major top-to-bottom.
    BMP rows are stored bottom-to-top and padded to a multiple of 4 bytes.
    """
    row_size_unpadded = width * 3
    padding           = (4 - row_size_unpadded % 4) % 4
    row_size          = row_size_unpadded + padding
    pixel_data_size   = row_size * height

    file_header_size  = 14
    dib_header_size   = 40
    header_total      = file_header_size + dib_header_size
    file_size         = header_total + pixel_data_size

    with open(path, 'wb') as f:
        # BITMAPFILEHEADER (14 bytes)
        f.write(b'BM')
        f.write(struct.pack('<I', file_size))
        f.write(struct.pack('<HH', 0, 0))          # reserved
        f.write(struct.pack('<I', header_total))   # pixel data offset

        # BITMAPINFOHEADER (40 bytes)
        f.write(struct.pack('<I', dib_header_size))
        f.write(struct.pack('<i', width))
        f.write(struct.pack('<i', -height))        # negative = top-down row order
        f.write(struct.pack('<H', 1))              # color planes
        f.write(struct.pack('<H', 24))             # bits per pixel
        f.write(struct.pack('<I', 0))              # no compression (BI_RGB)
        f.write(struct.pack('<I', pixel_data_size))
        f.write(struct.pack('<i', 2835))           # X pixels per meter (~72 dpi)
        f.write(struct.pack('<i', 2835))           # Y pixels per meter
        f.write(struct.pack('<I', 0))              # colors in table
        f.write(struct.pack('<I', 0))              # important colors

        # Pixel data (BMP channels are BGR order)
        pad = b'\x00' * padding
        for y in range(height):
            row_start = y * width
            row_bytes = bytearray(row_size_unpadded)
            for x in range(width):
                r, g, b = pixels[row_start + x]
                i = x * 3
                row_bytes[i]     = b
                row_bytes[i + 1] = g
                row_bytes[i + 2] = r
            f.write(row_bytes)
            f.write(pad)


# PNG writer (32-bit RGBA, written by Claude! not from me)

def _png_chunk(chunk_type, data):
    """Pack one PNG chunk: length + type + data + CRC."""
    c = chunk_type + data
    return (struct.pack('>I', len(data)) + c +
            struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF))

def write_png(path, width, height, pixels):
    """
    Write a 32-bit RGBA PNG file.

    pixels : flat list of (R, G, B, A) tuples, row-major top-to-bottom.
    Uses filter type 0 (None) per row — simple and lossless.
    """
    # Build raw image data: filter byte 0x00 followed by RGBA bytes per row
    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)          # filter type: None
        for x in range(width):
            r, g, b, a = pixels[y * width + x]
            raw_rows += bytes([r, g, b, a])

    with open(path, 'wb') as f:
        # PNG signature
        f.write(b'\x89PNG\r\n\x1a\n')

        # IHDR: width, height, bit depth=8, color type=6 (RGBA)
        ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
        f.write(_png_chunk(b'IHDR', ihdr_data))

        # IDAT: zlib-compressed image data
        f.write(_png_chunk(b'IDAT', zlib.compress(bytes(raw_rows), 9)))

        # IEND
        f.write(_png_chunk(b'IEND', b''))

# Taken & adapted from aseprite-nitro-scripts
def load_palette_bgr555(pal_data, num_colors=256):
    """
    Parse a raw BGR555 palette into a {index: (R, G, B)} dict.
    BGR555: bits 14-10=B, 9-5=G, 4-0=R, each channel 0-31 scaled to 0-255.
    """
    palette = {}
    for i in range(min(num_colors, len(pal_data) // 2)):
        entry = struct.unpack_from('<H', pal_data, i * 2)[0]
        r = ((entry >>  0) & 0x1F) * 8
        g = ((entry >>  5) & 0x1F) * 8
        b = ((entry >> 10) & 0x1F) * 8
        palette[i] = (r, g, b)
    return palette


# Main converter (written by me)

def convert(input_path, output_path=None, palette_path=None, scale=1, alpha=False):
    """
    Convert a croket_XX_LZ.bin file to a 24-bit BMP or 32-bit RGBA PNG.

    Parameters:
    input_path   : Path to the .bin source file.
    output_path  : Destination path. Defaults to <input>.bmp or <input>.png.
    palette_path : Optional raw BGR555 palette file — overrides embedded palette.
    scale        : Integer upscale factor, nearest-neighbour (default 1).
    alpha        : If True, export RGBA PNG with palette index 0 fully transparent.

    Returns the path where the output file was written.
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    data = input_path.read_bytes()

    # 1. Parse main header
    if len(data) < 0x20:
        raise ValueError("File too small to contain a valid header.")

    hdr_size   = struct.unpack_from('<I', data, 0x00)[0]
    map_offset = struct.unpack_from('<I', data, 0x04)[0]
    pal_offset = struct.unpack_from('<I', data, 0x08)[0]
    num_tiles  = struct.unpack_from('<H', data, 0x0C)[0]

    if hdr_size != 0x20:
        raise ValueError(
            f"Unexpected header size 0x{hdr_size:04X} (expected 0x0020). "
            "This may not be a supported Croket BG file.")

    tile_data_start = hdr_size                          # 0x20
    tile_data_end   = tile_data_start + num_tiles * 32  # should equal map_offset

    if tile_data_end != map_offset:
        print(f"Warning: tile data end (0x{tile_data_end:04X}) != "
              f"map_offset (0x{map_offset:04X}). Proceeding with map_offset.")

    # 2. Parse tilemap section header
    if map_offset + 0x10 > len(data):
        raise ValueError("map_offset points outside the file.")

    map_height_tiles = struct.unpack_from('<I', data, map_offset + 0x04)[0]
    map_width_tiles  = NDS_MAP_WIDTH_TILES

    map_data_start  = map_offset + 0x10
    map_data_end    = pal_offset
    num_map_entries = (map_data_end - map_data_start) // 2

    expected_entries = map_width_tiles * map_height_tiles
    if num_map_entries != expected_entries:
        print(f"Warning: expected {expected_entries} map entries "
              f"({map_width_tiles}x{map_height_tiles}), "
              f"found {num_map_entries}. Using minimum of both.")
        num_map_entries = min(num_map_entries, expected_entries)

    img_w = map_width_tiles  * 8
    img_h = map_height_tiles * 8

    # 3. Build palette
    #    Priority: --palette flag > embedded tail palette > default
    if palette_path:
        pal_bytes = Path(palette_path).read_bytes()
        palette = load_palette_bgr555(pal_bytes)
        print(f"Loaded palette from {palette_path} ({len(palette)} colors)")
    elif len(data) >= pal_offset + 32:
        palette = load_palette_bgr555(data[pal_offset:pal_offset + 32], num_colors=16)
        if not alpha:
            # Color 0 is the NDS transparency sentinel; render as black in BMP mode
            palette[0] = (0, 0, 0)
        print(f"Loaded embedded 16-color palette from 0x{pal_offset:04X}.")
    else:
        palette = DEFAULT_PALETTE
        print("No palette found — using default (white fill / dark outline).")

    # 4. Decode tiles (cached)
    tile_cache = {}

    def decode_tile(tile_idx):
        if tile_idx in tile_cache:
            return tile_cache[tile_idx]
        pix = [0] * 64
        if tile_idx >= 1:
            offset = tile_data_start + (tile_idx - 1) * 32
            if offset + 32 <= len(data):
                for i in range(32):
                    b = data[offset + i]
                    pix[i * 2]     =  b & 0x0F
                    pix[i * 2 + 1] = (b >> 4) & 0x0F
        tile_cache[tile_idx] = pix
        return pix

    # 5. Render tilemap into a flat pixel list
    out_pixels = [(0, 0, 0, 255)] * (img_w * img_h) if alpha else [(0, 0, 0)] * (img_w * img_h)

    for ti in range(num_map_entries):
        raw      = struct.unpack_from('<H', data, map_data_start + ti * 2)[0]
        tile_idx = raw & 0x03FF
        hflip    = bool((raw >> 10) & 1)
        vflip    = bool((raw >> 11) & 1)

        tile_x = (ti % map_width_tiles) * 8
        tile_y = (ti // map_width_tiles) * 8

        tile_pix = decode_tile(tile_idx)

        for py in range(8):
            src_py = (7 - py) if vflip else py
            for px in range(8):
                src_px  = (7 - px) if hflip else px
                pal_idx = tile_pix[src_py * 8 + src_px]
                if alpha:
                    if pal_idx == 0:
                        color = (0, 0, 0, 0)       # fully transparent
                    else:
                        r, g, b = palette.get(pal_idx, (255, 0, 255))
                        color = (r, g, b, 255)
                else:
                    color = palette.get(pal_idx, (255, 0, 255))
                out_pixels[(tile_y + py) * img_w + (tile_x + px)] = color

    # 6. Nearest-neighbour upscale
    if scale > 1:
        scaled_w = img_w * scale
        scaled_h = img_h * scale
        scaled   = [None] * (scaled_w * scaled_h)
        for sy in range(scaled_h):
            src_y = sy // scale
            for sx in range(scaled_w):
                src_x = sx // scale
                scaled[sy * scaled_w + sx] = out_pixels[src_y * img_w + src_x]
        out_pixels = scaled
        img_w, img_h = scaled_w, scaled_h

    # 7. Write output file
    if output_path is None:
        suffix = '.png' if alpha else '.bmp'
        output_path = str(input_path.with_suffix(suffix))

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    if alpha:
        write_png(output_path, img_w, img_h, out_pixels)
        print(f"Saved {img_w}x{img_h}px RGBA PNG -> {output_path}")
    else:
        write_bmp(output_path, img_w, img_h, out_pixels)
        print(f"Saved {img_w}x{img_h}px BMP -> {output_path}")
    return output_path


# CLI

def main():
    parser = argparse.ArgumentParser(
        description='Convert NDS croket_XX_LZ.bin sprite files to BMP '
                    '(no external dependencies).')
    parser.add_argument('input',
                        help='Source .bin file')
    parser.add_argument('output', nargs='?', default=None,
                        help='Destination BMP file (default: <input>.bmp)')
    parser.add_argument('--palette', '-p', default=None,
                        help='External BGR555 palette file — overrides embedded palette')
    parser.add_argument('--scale', '-s', type=int, default=1,
                        help='Nearest-neighbour upscale factor (default: 1)')

    parser.add_argument('--alpha', '-a', action='store_true',
                        help='Export RGBA PNG with palette index 0 as transparent '
                             '(default output extension becomes .png)')

    args = parser.parse_args()

    try:
        convert(
            input_path=args.input,
            output_path=args.output,
            palette_path=args.palette,
            scale=args.scale,
            alpha=args.alpha,
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
