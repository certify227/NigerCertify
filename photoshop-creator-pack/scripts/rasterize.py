#!/usr/bin/env python3
"""Rasterise le golden path (sortie de tests/visualize.js) pour les artefacts."""
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "preview" / "golden-path.json").read_text())
SCALE = 0.22
GAP = 28
PAD = 56
BG = (29, 29, 29)
TEXT = (244, 244, 244)
MUTED = (179, 179, 179)
BLUE = (138, 180, 248)
ACCENT = (38, 128, 235)
SAFE = (255, 90, 106)
BOARD = (34, 34, 34)
IMG = (61, 74, 99)
SUBJECT = (80, 130, 210)


def S(n):
    return int(round(n * SCALE))


def font(size):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", size)
    except OSError:
        return ImageFont.load_default()


canvas = data["canvas"]
story = data["story"]["frames"]
subject = data["subject"]
x = PAD
blocks = []
for item in canvas:
    w, h = S(item["preset"]["width"]), S(item["preset"]["height"])
    blocks.append((item, x, PAD + 36, w, h))
    x += w + GAP

story_y = PAD + 36 + max(b[4] for b in blocks) + 70
fw, fh = S(1080), S(1350)
width = max(blocks[-1][1] + blocks[-1][3], PAD + len(story) * (fw + 20) - 20) + PAD
height = story_y + fh + 64

img = Image.new("RGB", (width, height), BG)
d = ImageDraw.Draw(img)
d.text((PAD, 16), "Creator Pack — golden path  1080×1350 master → formats + PAS", fill=TEXT, font=font(18))

for item, bx, by, bw, bh in blocks:
    t = item["transform"]
    board = Image.new("RGBA", (bw, bh), (0, 0, 0, 0))
    bd = ImageDraw.Draw(board)
    bd.rectangle((0, 0, bw, bh), fill=BOARD + (255,))
    ix, iy = S(t["tx"]), S(t["ty"])
    bd.rectangle((ix, iy, ix + S(t["scaledW"]), iy + S(t["scaledH"])), fill=IMG + (255,))
    sx = S(subject["left"] * t["scale"])
    sy = S(t["ty"]) + S(subject["top"] * t["scale"])
    bd.rectangle(
        (sx, sy, sx + S(subject["width"] * t["scale"]), sy + S(subject["height"] * t["scale"])),
        fill=SUBJECT + (255,),
    )
    safe = item["safe"]
    bd.rectangle(
        (S(safe["left"]), S(safe["top"]), S(safe["right"]), S(safe["bottom"])),
        outline=SAFE + (255,),
        width=2,
    )
    # rounded mask
    mask = Image.new("L", (bw, bh), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, bw, bh), 8, fill=255)
    img.paste(board, (bx, by), mask)
    d.text((bx, by - 16), f"{item['preset']['short']}  {item['name']}", fill=TEXT, font=font(12))

d.text((PAD, story_y - 22), "Storyboard PAS", fill=TEXT, font=font(16))
for i, fr in enumerate(story):
    x0 = PAD + i * (fw + 20)
    d.rounded_rectangle((x0, story_y, x0 + fw, story_y + fh), 8, fill=(42, 42, 42), outline=ACCENT, width=2)
    d.text((x0 + 8, story_y + 10), fr["name"], fill=BLUE, font=font(12))
    d.text((x0 + 8, story_y + 28), fr["beat"]["title"], fill=TEXT, font=font(12))

notes = "   ·   ".join(
    f"{i['presetId']} hook {i['hook']['fit']['size']}pt"
    for i in data["type"]["items"]
)
d.text((PAD, height - 28), notes, fill=MUTED, font=font(12))

out = ROOT / "preview" / "golden-path.png"
img.save(out, "PNG")
print("wrote", out, img.size)
