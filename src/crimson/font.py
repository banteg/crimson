from __future__ import annotations

"""
Small font format + renderer for Crimsonland.

The small font is stored as a 256-byte width table (smallFnt.dat) and a
16x16 glyph atlas (smallWhite.png). Each glyph lives in a 16x16 cell; the
width table specifies the pixel advance per glyph.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PIL import Image


DEFAULT_SAMPLE = """CRIMSONLAND
The quick brown fox jumps over the lazy dog.
0123456789 !@#$%^&*()[]{}<>?/\\"""

GRID_SIZE = 16
CELL_SIZE = 16
WIDTH_TABLE_SIZE = 256


def _to_bytes(text: str | bytes) -> bytes:
    if isinstance(text, bytes):
        return text
    return text.encode("latin-1", errors="replace")


def _split_lines(data: bytes) -> list[bytes]:
    lines: list[bytearray] = [bytearray()]
    for value in data:
        if value == 0x0A:
            lines.append(bytearray())
            continue
        if value == 0x0D:
            continue
        lines[-1].append(value)
    return [bytes(line) for line in lines]


def _apply_tint(glyph: Image.Image, color: tuple[int, int, int, int]) -> Image.Image:
    if glyph.mode != "RGBA":
        glyph = glyph.convert("RGBA")
    r, g, b, a = color
    alpha = glyph.getchannel("A")
    if a != 255:
        alpha = alpha.point(lambda v: (v * a) // 255)
    tinted = Image.new("RGBA", glyph.size, (r, g, b, 0))
    tinted.putalpha(alpha)
    return tinted


@dataclass(frozen=True)
class SmallFont:
    widths: list[int]
    atlas: Image.Image
    grid: int = GRID_SIZE
    cell_size: int = CELL_SIZE

    def glyph_rect(self, idx: int, width: int | None = None) -> tuple[int, int, int, int]:
        if not 0 <= idx < WIDTH_TABLE_SIZE:
            raise ValueError(f"glyph index out of range: {idx}")
        row = idx // self.grid
        col = idx % self.grid
        cell_w = self.cell_size
        cell_h = self.cell_size
        x0 = col * cell_w
        y0 = row * cell_h
        if width is None:
            width = self.widths[idx]
        return x0, y0, x0 + width, y0 + cell_h

    def measure_text(self, text: str | bytes) -> int:
        data = _to_bytes(text)
        max_width = 0
        line_width = 0
        for value in data:
            if value == 0x0A:
                if line_width > max_width:
                    max_width = line_width
                line_width = 0
                continue
            if value == 0x0D:
                continue
            line_width += self.widths[value]
        if line_width > max_width:
            max_width = line_width
        return max_width

    def render_text(
        self,
        text: str | bytes,
        *,
        color: tuple[int, int, int, int] = (255, 255, 255, 255),
        scale: float = 1.0,
        background: tuple[int, int, int, int] = (0, 0, 0, 0),
    ) -> Image.Image:
        if scale <= 0:
            raise ValueError("scale must be positive")
        data = _to_bytes(text)
        lines = _split_lines(data)
        line_widths_px = []
        for line in lines:
            width_px = 0
            for value in line:
                width = self.widths[value]
                if width <= 0:
                    continue
                width_px += max(int(round(width * scale)), 1)
            line_widths_px.append(width_px)
        max_width = max(line_widths_px, default=0)
        line_height = int(round(self.cell_size * scale))
        out_width = max_width
        out_height = line_height * max(len(lines), 1)
        out_width = max(out_width, 1)
        out_height = max(out_height, 1)
        output = Image.new("RGBA", (out_width, out_height), background)

        for line_idx, line in enumerate(lines):
            x_px = 0
            y = line_idx * line_height
            for value in line:
                width = self.widths[value]
                if width <= 0:
                    continue
                x0, y0, x1, y1 = self.glyph_rect(value, width)
                glyph = self.atlas.crop((x0, y0, x1, y1))
                glyph_w = max(int(round(width * scale)), 1)
                glyph_h = max(line_height, 1)
                if scale != 1.0:
                    glyph = glyph.resize((glyph_w, glyph_h), resample=Image.NEAREST)
                if color != (255, 255, 255, 255):
                    glyph = _apply_tint(glyph, color)
                output.alpha_composite(glyph, dest=(x_px, y))
                x_px += glyph_w
        return output


def load_small_font(widths_path: str | Path, atlas_path: str | Path) -> SmallFont:
    widths = list(Path(widths_path).read_bytes())
    if len(widths) != WIDTH_TABLE_SIZE:
        raise ValueError(f"expected {WIDTH_TABLE_SIZE} bytes, got {len(widths)}")
    atlas = Image.open(atlas_path).convert("RGBA")
    return SmallFont(widths=widths, atlas=atlas)


def load_small_font_from_assets(assets_root: str | Path) -> SmallFont:
    root = Path(assets_root)
    widths_path = root / "crimson" / "load" / "smallFnt.dat"
    atlas_path = root / "crimson" / "load" / "smallWhite.png"
    return load_small_font(widths_path, atlas_path)


def render_sample(
    font: SmallFont,
    out_path: str | Path,
    text: str = DEFAULT_SAMPLE,
    *,
    scale: float = 2.0,
    color: tuple[int, int, int, int] = (255, 255, 255, 255),
) -> Path:
    output = font.render_text(text, color=color, scale=scale)
    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    output.save(dest)
    return dest


def main(argv: Iterable[str] | None = None) -> int:
    args = list(argv or [])
    assets_root = Path("assets")
    out_path = Path("output") / "small_font_sample.png"
    if args:
        out_path = Path(args[0])
    if len(args) > 1:
        assets_root = Path(args[1])
    font = load_small_font_from_assets(assets_root)
    render_sample(font, out_path)
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
