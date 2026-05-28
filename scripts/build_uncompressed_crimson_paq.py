#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from construct import ConstructError
from PIL import Image, UnidentifiedImageError

from crimson.atlas import rect_for_index
from grim import jaz, paq

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_ART_ROOT = REPO_ROOT / "artifacts" / "uncompressed_assets" / "crimsonland-2003-source-art-tga"
DEFAULT_BASE_PAQ = REPO_ROOT / "game_bins" / "crimsonland" / "1.9.93-gog" / "crimson.paq"
DEFAULT_OUTPUT_PAQ = REPO_ROOT / "artifacts" / "assets" / "crimson-uncompressed.paq"
BENIGN_ALPHA_MISMATCHES = frozenset(
    {
        "ter/fb_q1.jaz",
        "ter/fb_q2.jaz",
        "ter/fb_q3.jaz",
        "ter/fb_q4.jaz",
        "ui/ui_indpanel.jaz",
        "ui/ui_textlevelup.jaz",
    },
)
RUNTIME_RESIZED_REPLACEMENTS = frozenset(
    {
        # HUD code draws this full texture into 182x53 panel rectangles. The
        # source-art TGA is already 182x53, while the PAQ original is 128x64.
        "ui/ui_indpanel.jaz",
        # The runtime draws this full texture into a fixed 75x25 UI rect. The
        # source-art TGA is already 75x25, while the PAQ original is 64x32.
        "ui/ui_textlevelup.jaz",
    },
)
HYBRID_REPLACEMENTS = frozenset(
    {
        "game/bonuses.jaz",
        "game/projs.jaz",
        "ui/ui_wicons.jaz",
    },
)


@dataclass(frozen=True)
class BuildStats:
    entries: int
    replaced: int
    fallback: int
    skipped_alpha: int
    allowed_alpha: int
    skipped_visual: int
    hybrid: int
    input_payload_bytes: int
    output_payload_bytes: int


@dataclass(frozen=True)
class AlphaStats:
    size: tuple[int, int]
    nonopaque: int
    soft: int


@dataclass(frozen=True)
class Component:
    bbox: tuple[int, int, int, int]


@dataclass(frozen=True)
class HybridResult:
    payload: bytes
    mask: Image.Image


def _normalized_entry_name(name: str) -> str:
    return name.replace("\\", "/")


def _index_source_art(source_art_root: Path) -> dict[str, Path]:
    return {
        path.relative_to(source_art_root).as_posix().lower(): path
        for path in source_art_root.rglob("*")
        if path.is_file() and path.name != ".DS_Store"
    }


def _source_replacement_for(entry_name: str, source_art: dict[str, Path]) -> Path | None:
    lower_name = entry_name.lower()
    if lower_name.endswith(".jaz"):
        stem = lower_name[:-4]
        return source_art.get(f"{stem}.tga") or source_art.get(f"{stem}.jpg")
    if lower_name.endswith((".tga", ".jpg", ".jpeg", ".dat")):
        return source_art.get(lower_name)
    return None


def _alpha_stats(image: Image.Image) -> AlphaStats:
    rgba = image.convert("RGBA")
    alpha = bytes(rgba.getchannel("A").tobytes())
    return AlphaStats(
        size=rgba.size,
        nonopaque=sum(value < 255 for value in alpha),
        soft=sum(0 < value < 255 for value in alpha),
    )


def _premultiplied_visible_rgb(image: Image.Image) -> bytes:
    rgba = image.convert("RGBA")
    pixels = bytes(rgba.tobytes())
    out = bytearray()
    for idx in range(0, len(pixels), 4):
        r = pixels[idx]
        g = pixels[idx + 1]
        b = pixels[idx + 2]
        a = pixels[idx + 3]
        out.extend((r * a // 255, g * a // 255, b * a // 255))
    return bytes(out)


def _replacement_differs_visibly(original: Image.Image, replacement: Image.Image) -> bool:
    if original.size != replacement.size:
        return True

    original_rgb = _premultiplied_visible_rgb(original)
    replacement_rgb = _premultiplied_visible_rgb(replacement)
    pixel_count = original.size[0] * original.size[1]
    strong_pixels = 0
    max_delta = 0

    for idx in range(0, len(original_rgb), 3):
        delta = max(
            abs(original_rgb[idx] - replacement_rgb[idx]),
            abs(original_rgb[idx + 1] - replacement_rgb[idx + 1]),
            abs(original_rgb[idx + 2] - replacement_rgb[idx + 2]),
        )
        max_delta = max(max_delta, delta)
        if delta > 30:
            strong_pixels += 1

    return max_delta > 128 and strong_pixels / pixel_count > 0.01


def _hybrid_rects(entry_name: str, image_size: tuple[int, int]) -> tuple[Component, ...]:
    lower_name = entry_name.lower()
    width, height = image_size
    if lower_name == "game/bonuses.jaz":
        return tuple(Component(rect_for_index(width, height, 4, idx)) for idx in range(16))
    if lower_name == "game/projs.jaz":
        rects = {
            rect_for_index(width, height, 2, 0),
            rect_for_index(width, height, 4, 2),
            rect_for_index(width, height, 4, 3),
            rect_for_index(width, height, 4, 6),
        }
        return tuple(Component(rect) for rect in sorted(rects))
    if lower_name == "ui/ui_wicons.jaz":
        return tuple(
            Component(((idx % 4) * 64, (idx // 4) * 32, (idx % 4) * 64 + 64, (idx // 4) * 32 + 32)) for idx in range(32)
        )
    return ()


def _component_uses_original(component: Component, original: Image.Image, replacement: Image.Image) -> bool:
    original_pixels = original.convert("RGBA").tobytes()
    replacement_pixels = replacement.convert("RGBA").tobytes()
    width = original.width
    x0, y0, x1, y1 = component.bbox
    covered = 0
    strong = 0
    max_delta = 0
    nontransparent = 0

    for y in range(y0, y1):
        for x in range(x0, x1):
            idx = (y * width + x) * 4
            original_alpha = original_pixels[idx + 3]
            if original_alpha == 0:
                continue
            nontransparent += 1
            replacement_alpha = replacement_pixels[idx + 3]
            if replacement_alpha > 0:
                covered += 1
            delta = max(
                abs(original_pixels[idx] * original_alpha // 255 - replacement_pixels[idx] * replacement_alpha // 255),
                abs(
                    original_pixels[idx + 1] * original_alpha // 255
                    - replacement_pixels[idx + 1] * replacement_alpha // 255,
                ),
                abs(
                    original_pixels[idx + 2] * original_alpha // 255
                    - replacement_pixels[idx + 2] * replacement_alpha // 255,
                ),
            )
            max_delta = max(max_delta, delta)
            if delta > 80:
                strong += 1

    if nontransparent == 0:
        return False
    coverage = covered / nontransparent
    strong_ratio = strong / nontransparent
    return coverage < 0.98 or (max_delta > 160 and strong_ratio > 0.20)


def _paste_component(output: Image.Image, source: Image.Image, component: Component) -> None:
    x0, y0, _x1, _y1 = component.bbox
    output.alpha_composite(source.crop(component.bbox), (x0, y0))


def _paint_mask(mask: Image.Image, component: Component, color: tuple[int, int, int, int]) -> None:
    x0, y0, x1, y1 = component.bbox
    overlay = Image.new("RGBA", (x1 - x0, y1 - y0), color)
    mask.alpha_composite(overlay, (x0, y0))


def _encode_tga(image: Image.Image) -> bytes:
    out = BytesIO()
    image.save(out, format="TGA", compression="tga_rle")
    return out.getvalue()


def _hybrid_replacement(entry_name: str, original_payload: bytes, replacement: Path) -> HybridResult | None:
    if entry_name.lower() not in HYBRID_REPLACEMENTS:
        return None
    try:
        original = _decode_original_image(entry_name, original_payload)
        if original is None:
            return None
        original = original.convert("RGBA")
        replacement_image = Image.open(replacement).convert("RGBA")
    except (ConstructError, OSError, UnidentifiedImageError, ValueError):
        return None
    if original.size != replacement_image.size:
        return None

    output = original.copy()
    mask = Image.new("RGBA", original.size, (0, 0, 0, 0))
    for component in _hybrid_rects(entry_name, original.size):
        use_original = _component_uses_original(component, original, replacement_image)
        source = original if use_original else replacement_image
        _paste_component(output, source, component)
        _paint_mask(mask, component, (255, 96, 96, 160) if use_original else (96, 180, 255, 160))
    return HybridResult(payload=_encode_tga(output), mask=mask)


def _decode_original_image(entry_name: str, payload: bytes) -> Image.Image | None:
    lower_name = entry_name.lower()
    if lower_name.endswith(".jaz"):
        return jaz.decode_jaz_bytes(payload).composite_image()
    if lower_name.endswith((".tga", ".jpg", ".jpeg")):
        return Image.open(BytesIO(payload))
    return None


def _replacement_degrades_alpha(entry_name: str, original_payload: bytes, replacement: Path) -> bool:
    try:
        original = _decode_original_image(entry_name, original_payload)
        if original is None:
            return False

        original_alpha = _alpha_stats(original)
        replacement_alpha = _alpha_stats(Image.open(replacement))
    except (ConstructError, OSError, UnidentifiedImageError, ValueError):
        return False
    return (
        replacement_alpha.size != original_alpha.size
        or replacement_alpha.nonopaque < original_alpha.nonopaque
        or replacement_alpha.soft < original_alpha.soft
    )


def _allows_alpha_mismatch(entry_name: str) -> bool:
    return entry_name.lower() in BENIGN_ALPHA_MISMATCHES


def _allows_visual_mismatch(entry_name: str) -> bool:
    return entry_name.lower() in RUNTIME_RESIZED_REPLACEMENTS


def _replacement_degrades_visual(entry_name: str, original_payload: bytes, replacement: Path) -> bool:
    try:
        original = _decode_original_image(entry_name, original_payload)
        if original is None:
            return False
        return _replacement_differs_visibly(original, Image.open(replacement))
    except (ConstructError, OSError, UnidentifiedImageError, ValueError):
        return False


def build_uncompressed_crimson_paq(source_art_root: Path, base_paq: Path, output_paq: Path) -> BuildStats:
    source_art = _index_source_art(source_art_root)
    output_entries: list[tuple[str, bytes]] = []
    replaced = 0
    fallback = 0
    skipped_alpha = 0
    allowed_alpha = 0
    skipped_visual = 0
    hybrid = 0
    input_payload_bytes = 0
    output_payload_bytes = 0

    for original_name, original_payload in paq.iter_entries(base_paq):
        entry_name = _normalized_entry_name(original_name)
        input_payload_bytes += len(original_payload)
        replacement = _source_replacement_for(entry_name, source_art)
        hybrid_result = _hybrid_replacement(entry_name, original_payload, replacement) if replacement else None
        if hybrid_result is not None:
            payload = hybrid_result.payload
            output_name = replacement.relative_to(source_art_root).as_posix()
            replaced += 1
            hybrid += 1
            output_payload_bytes += len(payload)
            output_entries.append((output_name, payload))
            continue

        if replacement is not None and _replacement_degrades_alpha(entry_name, original_payload, replacement):
            if _allows_alpha_mismatch(entry_name):
                allowed_alpha += 1
            else:
                replacement = None
                skipped_alpha += 1
        if (
            replacement is not None
            and not _allows_visual_mismatch(entry_name)
            and _replacement_degrades_visual(entry_name, original_payload, replacement)
        ):
            replacement = None
            skipped_visual += 1

        if replacement is None:
            payload = original_payload
            output_name = entry_name
            fallback += 1
        else:
            payload = replacement.read_bytes()
            output_name = replacement.relative_to(source_art_root).as_posix()
            replaced += 1

        output_payload_bytes += len(payload)
        output_entries.append((output_name, payload))

    output_paq.parent.mkdir(parents=True, exist_ok=True)
    paq.write_paq(output_paq, output_entries)
    return BuildStats(
        entries=len(output_entries),
        replaced=replaced,
        fallback=fallback,
        skipped_alpha=skipped_alpha,
        allowed_alpha=allowed_alpha,
        skipped_visual=skipped_visual,
        hybrid=hybrid,
        input_payload_bytes=input_payload_bytes,
        output_payload_bytes=output_payload_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build crimson.paq variant from source-art TGA/JPG files.")
    parser.add_argument("--source-art-root", type=Path, default=DEFAULT_SOURCE_ART_ROOT)
    parser.add_argument("--base-paq", type=Path, default=DEFAULT_BASE_PAQ)
    parser.add_argument("--output-paq", type=Path, default=DEFAULT_OUTPUT_PAQ)
    args = parser.parse_args()

    stats = build_uncompressed_crimson_paq(args.source_art_root, args.base_paq, args.output_paq)
    print(f"wrote {args.output_paq}")
    print(
        "entries={entries} replaced={replaced} fallback={fallback} "
        "skipped_alpha={skipped_alpha} allowed_alpha={allowed_alpha} skipped_visual={skipped_visual} hybrid={hybrid} "
        "payload_bytes={input_payload_bytes}->{output_payload_bytes}".format(
            **stats.__dict__,
        ),
    )


if __name__ == "__main__":
    main()
