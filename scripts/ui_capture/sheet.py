import sys
from pathlib import Path

from PIL import Image, ImageDraw

out, *paths = sys.argv[1:]
w, h, cols = 640, 480, 3
rows = (len(paths) + cols - 1) // cols
sheet = Image.new("RGB", (w * cols, h * rows))
for i, p in enumerate(paths):
    im = Image.open(p).convert("RGB").resize((w, h))
    ImageDraw.Draw(im).text((6, 6), Path(p).stem, fill=(255, 0, 255))
    sheet.paste(im, ((i % cols) * w, (i // cols) * h))
sheet.save(out)
