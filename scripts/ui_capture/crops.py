"""usage: crops.py out.png base_dir new_dir name:x0,y0,x1,y1 ... -> rows of before|after crops at 2x."""
import sys
from pathlib import Path

from PIL import Image, ImageDraw

out, base, new, *specs = sys.argv[1:]
rows = []
for spec in specs:
    name, box = spec.split(":")
    box = tuple(int(v) for v in box.split(","))
    a = Image.open(Path(base) / name).convert("RGB").crop(box)
    b = Image.open(Path(new) / name).convert("RGB").crop(box)
    w, h = a.size
    row = Image.new("RGB", (w * 4 + 8, h * 2 + 14), (40, 0, 40))
    row.paste(a.resize((w * 2, h * 2), Image.NEAREST), (0, 14))
    row.paste(b.resize((w * 2, h * 2), Image.NEAREST), (w * 2 + 8, 14))
    ImageDraw.Draw(row).text((2, 1), f"{name}  before | after", fill=(255, 0, 255))
    rows.append(row)
W = max(r.width for r in rows)
sheet = Image.new("RGB", (W, sum(r.height for r in rows)))
y = 0
for r in rows:
    sheet.paste(r, (0, y)); y += r.height
sheet.save(out)
