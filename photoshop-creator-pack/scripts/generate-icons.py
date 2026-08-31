#!/usr/bin/env python3
"""Génère les icônes UXP (panel + plugin list) du Creator Pack."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1] / "plugin" / "icons"
ROOT.mkdir(parents=True, exist_ok=True)

BLUE = (20, 115, 230, 255)
BLUE_DK = (13, 86, 180, 255)
WHITE = (255, 255, 255, 255)
DARK = (44, 44, 44, 255)


def rounded_rect(draw, box, radius, fill):
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def draw_mark(img, pad=0.18):
    d = ImageDraw.Draw(img)
    w, h = img.size
    m = int(w * pad)
    r = max(3, int(w * 0.22))
    rounded_rect(d, (m, m, w - m, h - m), r, BLUE)
    inner = m + max(2, w // 16)
    # trois formats (feed / story / thumb)
    gap = max(1, w // 24)
    col_w = (w - inner * 2 - gap * 2) / 3
    x0 = inner
    y0 = inner + max(1, h // 14)
    y1 = h - inner
    # 4:5
    x1 = x0 + col_w
    d.rounded_rectangle((x0, y0 + (y1 - y0) * 0.12, x1 - gap / 2, y1), radius=max(1, w // 28), fill=WHITE)
    # 9:16
    x2 = x1 + col_w
    d.rounded_rectangle((x1 + gap / 2, y0, x2 - gap / 2, y1), radius=max(1, w // 28), fill=(230, 242, 255, 255))
    # 16:9
    x3 = x2 + col_w
    mid_h = (y1 - y0) * 0.42
    cy = (y0 + y1) / 2
    d.rounded_rectangle((x2 + gap / 2, cy - mid_h / 2, x3, cy + mid_h / 2), radius=max(1, w // 28), fill=WHITE)
    return img


def save(name, size, bg=None):
    img = Image.new("RGBA", (size, size), bg or (0, 0, 0, 0))
    draw_mark(img)
    img.save(ROOT / name, "PNG")


def main():
    save("plugin.png", 48)
    save("plugin@2x.png", 96)
    save("dark.png", 23)
    save("dark@2x.png", 46)
    save("light.png", 23)
    save("light@2x.png", 46)
    # plugin list sometimes prefers opaque
    opaque = Image.new("RGBA", (48, 48), DARK)
    opaque.alpha_composite(Image.open(ROOT / "plugin.png"))
    opaque.save(ROOT / "plugin_opaque.png", "PNG")
    print(f"icons -> {ROOT}")


if __name__ == "__main__":
    main()
