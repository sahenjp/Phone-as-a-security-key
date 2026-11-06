#!/usr/bin/env python3
"""Generate placeholder MSIX tile assets (windows/Assets/*.png).

Pure-stdlib PNG writer. The art is intentionally simple - a white key
glyph on indigo, matching the "key inside a phone" motif - because the
project logo is being designed separately. Regenerate any time with:

    python3 windows/tools/make-assets.py

Assets produced (sizes follow the MSIX tile template):
    StoreLogo.png 50x50, Square44x44Logo.png, Square71x71Logo.png,
    Square150x150Logo.png, Square310x310Logo.png,
    Wide310x150Logo.png 310x150, SplashScreen.png 620x300
"""

import math
import os
import struct
import zlib

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Assets")

BG = (49, 46, 129)        # indigo-900
FG = (255, 255, 255)      # white glyph


def dist_to_segment(px, py, x1, y1, x2, y2):
    dx, dy = x2 - x1, y2 - y1
    if dx == 0 and dy == 0:
        return math.hypot(px - x1, py - y1)
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))


def glyph_on(px, py, w, h):
    """True if pixel (px, py) is part of the key glyph. Coordinates are
    normalized so the glyph scales with the tile: ring top-left area,
    shaft running diagonally down-right, two teeth near the tip."""
    s = min(w, h)
    cx, cy = w / 2.0, h / 2.0
    # Phone outline: rounded rect border.
    m = 0.16 * s            # margin
    r = 0.09 * s            # corner radius
    pw, ph = 0.44 * s, 0.68 * s
    x0, y0 = cx - pw / 2, cy - ph / 2
    x1, y1 = cx + pw / 2, cy + ph / 2
    # Distance to rounded-rect edge band.
    qx = max(x0 + r - px, 0, px - (x1 - r))
    qy = max(y0 + r - py, 0, py - (y1 - r))
    d_edge = math.hypot(qx, qy) if (qx or qy) else min(px - x0, x1 - px, py - y0, y1 - py)
    inside = x0 <= px <= x1 and y0 <= py <= y1
    if inside and d_edge <= 0.028 * s:
        return True
    # Key ring: annulus.
    kx, ky = cx - 0.07 * s, cy - 0.10 * s
    d = math.hypot(px - kx, py - ky)
    if abs(d - 0.085 * s) <= 0.026 * s:
        return True
    # Key shaft: from ring toward bottom-right.
    tipx, tipy = cx + 0.10 * s, cy + 0.13 * s
    if dist_to_segment(px, py, kx, ky, tipx, tipy) <= 0.024 * s:
        return True
    # Teeth: two short strokes near the tip.
    t1x, t1y = cx + 0.055 * s, cy + 0.085 * s
    if dist_to_segment(px, py, t1x, t1y, t1x + 0.045 * s, t1y - 0.01 * s) <= 0.020 * s:
        return True
    t2x, t2y = cx + 0.085 * s, cy + 0.115 * s
    if dist_to_segment(px, py, t2x, t2y, t2x + 0.04 * s, t2y - 0.01 * s) <= 0.020 * s:
        return True
    return False


def render(w, h):
    rows = []
    for y in range(h):
        row = bytearray()
        row.append(0)  # PNG filter: none
        for x in range(w):
            rgb = FG if glyph_on(x + 0.5, y + 0.5, w, h) else BG
            row += bytes((rgb[0], rgb[1], rgb[2], 255))
        rows.append(bytes(row))
    return b"".join(rows)


def write_png(path, w, h):
    def chunk(typ, data):
        c = struct.pack(">I", len(data)) + typ + data
        c += struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)
        return c

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(render(w, h), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)
    print(f"{path} ({w}x{h}, {len(png)} bytes)")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, w, h in [
        ("StoreLogo.png", 50, 50),
        ("Square44x44Logo.png", 44, 44),
        ("Square71x71Logo.png", 71, 71),
        ("Square150x150Logo.png", 150, 150),
        ("Square310x310Logo.png", 310, 310),
        ("Wide310x150Logo.png", 310, 150),
        ("SplashScreen.png", 620, 300),
    ]:
        write_png(os.path.join(OUT_DIR, name), w, h)


if __name__ == "__main__":
    main()
