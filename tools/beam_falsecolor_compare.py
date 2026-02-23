#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Final

from PIL import Image, ImageDraw

ColorStop = tuple[float, tuple[int, int, int]]

NEGATIVE_STOPS: Final[list[ColorStop]] = [
    (0.0, (0, 0, 0)),
    (0.35, (20, 40, 120)),
    (0.70, (20, 140, 240)),
    (1.0, (200, 255, 255)),
]

POSITIVE_STOPS: Final[list[ColorStop]] = [
    (0.0, (0, 0, 0)),
    (0.35, (120, 35, 10)),
    (0.70, (255, 140, 20)),
    (1.0, (255, 245, 140)),
]

MAGNITUDE_STOPS: Final[list[ColorStop]] = [
    (0.0, (0, 0, 0)),
    (0.20, (18, 20, 85)),
    (0.40, (40, 80, 180)),
    (0.60, (50, 170, 235)),
    (0.80, (255, 190, 40)),
    (1.0, (255, 255, 220)),
]


def _clamp01(value: float) -> float:
    if value <= 0.0:
        return 0.0
    if value >= 1.0:
        return 1.0
    return value


def _lerp_u8(a: int, b: int, t: float) -> int:
    out = float(a) * (1.0 - t) + float(b) * t
    return max(0, min(255, int(round(out))))


def _sample_stops(stops: list[ColorStop], t: float) -> tuple[int, int, int]:
    if not stops:
        return 0, 0, 0
    t = _clamp01(t)
    if t <= stops[0][0]:
        return stops[0][1]
    if t >= stops[-1][0]:
        return stops[-1][1]
    for idx in range(1, len(stops)):
        left_pos, left_color = stops[idx - 1]
        right_pos, right_color = stops[idx]
        if t <= right_pos:
            span = max(1e-9, float(right_pos) - float(left_pos))
            local_t = (float(t) - float(left_pos)) / span
            return (
                _lerp_u8(left_color[0], right_color[0], local_t),
                _lerp_u8(left_color[1], right_color[1], local_t),
                _lerp_u8(left_color[2], right_color[2], local_t),
            )
    return stops[-1][1]


def _beam_luma(px: tuple[int, int, int]) -> int:
    r, g, b = px
    return max(int(r), int(g), int(b))


def _parse_roi(text: str | None, *, width: int, height: int) -> tuple[int, int, int, int] | None:
    if text is None:
        return None
    parts = [part.strip() for part in text.split(",")]
    if len(parts) != 4:
        raise ValueError("roi must be x0,y0,x1,y1")
    x0, y0, x1, y1 = (int(part, 10) for part in parts)
    x0 = max(0, min(width, x0))
    y0 = max(0, min(height, y0))
    x1 = max(0, min(width, x1))
    y1 = max(0, min(height, y1))
    if x1 <= x0 or y1 <= y0:
        raise ValueError("roi must satisfy x1>x0 and y1>y0 inside image bounds")
    return x0, y0, x1, y1


def _build_panels(
    *,
    baseline: Image.Image,
    candidate: Image.Image,
    signed_clip: float,
    abs_clip: float,
    neutral_band: float,
    stripe_px: int,
) -> tuple[list[tuple[str, Image.Image]], dict[str, float]]:
    width, height = baseline.size
    baseline_bytes = baseline.tobytes()
    candidate_bytes = candidate.tobytes()

    baseline_gray_data: list[tuple[int, int, int]] = []
    candidate_gray_data: list[tuple[int, int, int]] = []
    signed_data: list[tuple[int, int, int]] = []
    magnitude_data: list[tuple[int, int, int]] = []
    overlay_data: list[tuple[int, int, int]] = []
    stripe_data: list[tuple[int, int, int]] = []

    abs_sum = 0.0
    signed_sum = 0.0
    under_sum = 0.0
    over_sum = 0.0

    signed_den = max(1e-6, float(signed_clip) * 255.0)
    abs_den = max(1e-6, float(abs_clip) * 255.0)
    neutral = max(0.0, float(neutral_band) * 255.0)
    stripe_px = max(1, int(stripe_px))

    pixel_count = width * height
    for pixel_idx in range(pixel_count):
        offset = pixel_idx * 3
        base_rgb = (
            int(baseline_bytes[offset + 0]),
            int(baseline_bytes[offset + 1]),
            int(baseline_bytes[offset + 2]),
        )
        cand_rgb = (
            int(candidate_bytes[offset + 0]),
            int(candidate_bytes[offset + 1]),
            int(candidate_bytes[offset + 2]),
        )
        x = pixel_idx % width
        base_l = _beam_luma(base_rgb)
        cand_l = _beam_luma(cand_rgb)
        diff = int(cand_l) - int(base_l)
        abs_diff = abs(diff)

        abs_sum += float(abs_diff)
        signed_sum += float(diff)
        if diff < 0:
            under_sum += float(-diff)
        elif diff > 0:
            over_sum += float(diff)

        baseline_gray_data.append((base_l, base_l, base_l))
        candidate_gray_data.append((cand_l, cand_l, cand_l))

        if float(abs_diff) <= neutral:
            signed_color = (0, 0, 0)
        elif diff > 0:
            t = _clamp01(float(abs_diff) / signed_den)
            signed_color = _sample_stops(POSITIVE_STOPS, t)
        else:
            t = _clamp01(float(abs_diff) / signed_den)
            signed_color = _sample_stops(NEGATIVE_STOPS, t)
        signed_data.append(signed_color)

        t_abs = _clamp01(float(abs_diff) / abs_den)
        magnitude_data.append(_sample_stops(MAGNITUDE_STOPS, t_abs))

        # Base grayscale context with signed tint layer for shape tracing.
        base_dim = int(round(float(base_l) * 0.60))
        signed_mix = (
            min(255, int(round(base_dim + float(signed_color[0]) * 0.70))),
            min(255, int(round(base_dim + float(signed_color[1]) * 0.70))),
            min(255, int(round(base_dim + float(signed_color[2]) * 0.70))),
        )
        overlay_data.append(signed_mix)

        stripe_source = base_rgb if ((x // stripe_px) % 2 == 0) else cand_rgb
        stripe_data.append(stripe_source)

    baseline_gray = Image.new("RGB", (width, height))
    candidate_gray = Image.new("RGB", (width, height))
    signed_map = Image.new("RGB", (width, height))
    magnitude_map = Image.new("RGB", (width, height))
    overlay = Image.new("RGB", (width, height))
    stripe = Image.new("RGB", (width, height))

    baseline_gray.putdata(baseline_gray_data)
    candidate_gray.putdata(candidate_gray_data)
    signed_map.putdata(signed_data)
    magnitude_map.putdata(magnitude_data)
    overlay.putdata(overlay_data)
    stripe.putdata(stripe_data)

    panel_list = [
        ("baseline (luma)", baseline_gray),
        ("candidate (luma)", candidate_gray),
        ("signed diff", signed_map),
        ("abs diff heat", magnitude_map),
        ("signed overlay", overlay),
        ("stripe split", stripe),
    ]

    total = max(1.0, float(width * height * 255))
    stats = {
        "mae": float(abs_sum / total),
        "signed_bias": float(signed_sum / total),
        "underdraw": float(under_sum / total),
        "overdraw": float(over_sum / total),
        "width": float(width),
        "height": float(height),
    }
    return panel_list, stats


def _crop_and_zoom(
    image: Image.Image,
    *,
    roi: tuple[int, int, int, int] | None,
    zoom: int,
) -> Image.Image:
    out = image.crop(roi) if roi is not None else image
    zoom = max(1, int(zoom))
    if zoom > 1:
        out = out.resize((out.width * zoom, out.height * zoom), Image.Resampling.NEAREST)
    return out


def _compose_sheet(
    *,
    panels: list[tuple[str, Image.Image]],
    title: str,
) -> Image.Image:
    if len(panels) != 6:
        raise ValueError("expected six panels")
    panel_w = panels[0][1].width
    panel_h = panels[0][1].height
    margin = 20
    col_gap = 16
    row_gap = 22
    panel_label_h = 18
    top_h = 44

    width = margin * 2 + panel_w * 3 + col_gap * 2
    height = top_h + margin * 2 + panel_h * 2 + panel_label_h * 2 + row_gap

    canvas = Image.new("RGB", (width, height), (0, 0, 0))
    draw = ImageDraw.Draw(canvas)

    draw.text((margin, 10), title, fill=(235, 235, 245))
    draw.text((margin, 26), "signed: cyan=baseline brighter, orange=candidate brighter", fill=(150, 165, 190))

    for idx, (label, panel) in enumerate(panels):
        row = idx // 3
        col = idx % 3
        x = margin + col * (panel_w + col_gap)
        y = top_h + margin + row * (panel_h + panel_label_h + row_gap)
        draw.text((x, y), label, fill=(205, 215, 235))
        canvas.paste(panel, (x, y + panel_label_h))
    return canvas


def main() -> int:
    parser = argparse.ArgumentParser(description="Create faux-colormap visual diff panels for beam renders.")
    parser.add_argument("--baseline", required=True, help="path to baseline image")
    parser.add_argument("--candidate", required=True, help="path to candidate image")
    parser.add_argument("--out", required=True, help="output composite image path")
    parser.add_argument("--stats-out", help="optional output json for summary stats")
    parser.add_argument("--title", default="beam visual compare")
    parser.add_argument("--roi", help="optional crop as x0,y0,x1,y1")
    parser.add_argument("--zoom", type=int, default=1, help="integer nearest-neighbor zoom after crop")
    parser.add_argument("--signed-clip", type=float, default=0.35, help="diff saturation for signed map, in [0,1]")
    parser.add_argument("--abs-clip", type=float, default=0.35, help="diff saturation for abs heatmap, in [0,1]")
    parser.add_argument("--neutral-band", type=float, default=0.01, help="signed deadband around zero, in [0,1]")
    parser.add_argument("--stripe-px", type=int, default=8, help="stripe width for baseline/candidate split panel")
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    candidate_path = Path(args.candidate)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    baseline = Image.open(baseline_path).convert("RGB")
    candidate = Image.open(candidate_path).convert("RGB")
    if baseline.size != candidate.size:
        raise ValueError(
            f"image sizes differ: baseline={baseline.size} candidate={candidate.size}; use same-size captures",
        )

    roi = _parse_roi(args.roi, width=baseline.width, height=baseline.height)
    panel_list, stats = _build_panels(
        baseline=baseline,
        candidate=candidate,
        signed_clip=float(args.signed_clip),
        abs_clip=float(args.abs_clip),
        neutral_band=float(args.neutral_band),
        stripe_px=int(args.stripe_px),
    )
    panel_list = [
        (
            label,
            _crop_and_zoom(panel, roi=roi, zoom=int(args.zoom)),
        )
        for label, panel in panel_list
    ]
    sheet = _compose_sheet(panels=panel_list, title=str(args.title))
    sheet.save(out_path)

    stats_payload = {
        "baseline": str(baseline_path),
        "candidate": str(candidate_path),
        "roi": None if roi is None else [int(v) for v in roi],
        "zoom": int(args.zoom),
        "signed_clip": float(args.signed_clip),
        "abs_clip": float(args.abs_clip),
        "neutral_band": float(args.neutral_band),
        "stripe_px": int(args.stripe_px),
        "stats": stats,
    }
    if args.stats_out:
        stats_path = Path(args.stats_out)
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        stats_path.write_text(json.dumps(stats_payload, indent=2), encoding="utf-8")

    print(
        json.dumps(
            {
                "out": str(out_path),
                "mae": round(float(stats["mae"]), 6),
                "underdraw": round(float(stats["underdraw"]), 6),
                "overdraw": round(float(stats["overdraw"]), 6),
            },
            indent=2,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
