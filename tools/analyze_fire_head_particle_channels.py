#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw

# Keep defaults in sync with beam_debug stamped-virtual fire glow overlay path.
FIT_A = 1.22
FIT_B = -4.7
FIT_P = 1.1
FIT_C = 0.015
FIT_GAIN = 2.0
FIT_RGB = (1.0, 233.0 / 255.0, 131.0 / 255.0)


@dataclass(frozen=True, slots=True)
class ChannelStats:
    mae: float
    rmse: float
    bias: float
    corr: float


def _clamp01(value: float) -> float:
    if value <= 0.0:
        return 0.0
    if value >= 1.0:
        return 1.0
    return float(value)


def _profile(d_norm: float, *, a: float, b: float, p: float, c: float, gain: float) -> float:
    d_pow = max(0.0, float(d_norm)) ** max(0.01, float(p))
    decay = max(0.0, float(-b))
    v = float(a) * math.exp(-decay * d_pow) - float(c)
    return _clamp01(v) * max(0.0, float(gain))


def _render_analytic_rgba(
    *,
    size: int,
    a: float,
    b: float,
    p: float,
    c: float,
    gain: float,
    rgb: tuple[float, float, float],
) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 255))
    cx = (size - 1) * 0.5
    cy = (size - 1) * 0.5
    radius = max(1.0, size * 0.5)
    px = img.load()
    for y in range(size):
        for x in range(size):
            dx = (float(x) - cx) / radius
            dy = (float(y) - cy) / radius
            d_norm = math.sqrt(dx * dx + dy * dy)
            alpha = _profile(d_norm, a=a, b=b, p=p, c=c, gain=gain)
            rr = int(round(_clamp01(float(rgb[0]) * alpha) * 255.0))
            gg = int(round(_clamp01(float(rgb[1]) * alpha) * 255.0))
            bb = int(round(_clamp01(float(rgb[2]) * alpha) * 255.0))
            px[x, y] = (rr, gg, bb, 255)
    return img


def _corr(a: list[float], b: list[float]) -> float:
    n = min(len(a), len(b))
    if n <= 1:
        return 0.0
    ma = sum(a[:n]) / float(n)
    mb = sum(b[:n]) / float(n)
    num = 0.0
    da = 0.0
    db = 0.0
    for i in range(n):
        xa = float(a[i]) - ma
        xb = float(b[i]) - mb
        num += xa * xb
        da += xa * xa
        db += xb * xb
    den = math.sqrt(max(1e-12, da * db))
    return float(num / den)


def _channel_stats(ref: list[float], cand: list[float]) -> ChannelStats:
    n = min(len(ref), len(cand))
    if n <= 0:
        return ChannelStats(mae=0.0, rmse=0.0, bias=0.0, corr=0.0)
    abs_sum = 0.0
    sq_sum = 0.0
    bias_sum = 0.0
    for i in range(n):
        d = float(cand[i]) - float(ref[i])
        abs_sum += abs(d)
        sq_sum += d * d
        bias_sum += d
    return ChannelStats(
        mae=float(abs_sum / n),
        rmse=float(math.sqrt(sq_sum / n)),
        bias=float(bias_sum / n),
        corr=_corr(ref[:n], cand[:n]),
    )


def _fit_channel_scale(ref: list[float], cand_unit: list[float]) -> float:
    num = 0.0
    den = 0.0
    for r, c in zip(ref, cand_unit, strict=False):
        rr = float(r)
        cc = float(c)
        num += rr * cc
        den += cc * cc
    if den <= 1e-9:
        return 1.0
    return max(0.0, num / den)


def _collect_channels(img: Image.Image) -> tuple[list[float], list[float], list[float]]:
    rgb = img.convert("RGB")
    data = list(rgb.getdata())
    r = [float(p[0]) / 255.0 for p in data]
    g = [float(p[1]) / 255.0 for p in data]
    b = [float(p[2]) / 255.0 for p in data]
    return r, g, b


def _draw_triptych(*, out_path: Path, baseline: Image.Image, analytic: Image.Image, tuned: Image.Image) -> None:
    w, h = baseline.size
    margin = 14
    title_h = 34
    out = Image.new("RGB", (margin * 4 + w * 3, margin * 2 + title_h + h), (0, 0, 0))
    out.paste(baseline.convert("RGB"), (margin, margin + title_h))
    out.paste(analytic.convert("RGB"), (margin * 2 + w, margin + title_h))
    out.paste(tuned.convert("RGB"), (margin * 3 + w * 2, margin + title_h))
    d = ImageDraw.Draw(out)
    d.text((margin, margin), "baseline_bilinear", fill=(220, 230, 245))
    d.text((margin * 2 + w, margin), "analytic_raw", fill=(220, 230, 245))
    d.text((margin * 3 + w * 2, margin), "analytic_tuned_rgb", fill=(220, 230, 245))
    out.save(out_path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze isolated fire head particle channels: texture baseline vs analytic overlay output.",
    )
    parser.add_argument("--source", default="artifacts/beam/fire_overlay_glow_source_cell.png")
    parser.add_argument("--size", type=int, default=64, help="comparison render size (default: 64)")
    parser.add_argument("--out-json", default="artifacts/beam/fire_head_particle_channel_report.json")
    parser.add_argument("--out-triptych", default="artifacts/beam/fire_head_particle_channel_triptych.png")
    parser.add_argument("--out-analytic-raw", default="artifacts/beam/fire_head_particle_analytic_raw.png")
    parser.add_argument("--out-analytic-tuned", default="artifacts/beam/fire_head_particle_analytic_tuned.png")
    args = parser.parse_args()

    src_path = Path(str(args.source))
    baseline_src = Image.open(src_path).convert("RGBA")
    size = max(8, int(args.size))
    baseline = baseline_src.resize((size, size), Image.Resampling.BILINEAR)

    analytic_raw = _render_analytic_rgba(
        size=size,
        a=FIT_A,
        b=FIT_B,
        p=FIT_P,
        c=FIT_C,
        gain=FIT_GAIN,
        rgb=FIT_RGB,
    )

    br, bg, bb = _collect_channels(baseline)
    ar, ag, ab = _collect_channels(analytic_raw)

    raw_stats = {
        "r": _channel_stats(br, ar),
        "g": _channel_stats(bg, ag),
        "b": _channel_stats(bb, ab),
    }

    # Fit only color multipliers with fixed shape profile to isolate channel mismatch.
    unit = _render_analytic_rgba(
        size=size,
        a=FIT_A,
        b=FIT_B,
        p=FIT_P,
        c=FIT_C,
        gain=FIT_GAIN,
        rgb=(1.0, 1.0, 1.0),
    )
    ur, ug, ub = _collect_channels(unit)
    k_r = _fit_channel_scale(br, ur)
    k_g = _fit_channel_scale(bg, ug)
    k_b = _fit_channel_scale(bb, ub)
    tuned_rgb = (_clamp01(k_r), _clamp01(k_g), _clamp01(k_b))

    analytic_tuned = _render_analytic_rgba(
        size=size,
        a=FIT_A,
        b=FIT_B,
        p=FIT_P,
        c=FIT_C,
        gain=FIT_GAIN,
        rgb=tuned_rgb,
    )
    tr, tg, tb = _collect_channels(analytic_tuned)
    tuned_stats = {
        "r": _channel_stats(br, tr),
        "g": _channel_stats(bg, tg),
        "b": _channel_stats(bb, tb),
    }

    out_json = Path(str(args.out_json))
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_raw = Path(str(args.out_analytic_raw))
    out_tuned = Path(str(args.out_analytic_tuned))
    out_triptych = Path(str(args.out_triptych))
    out_raw.parent.mkdir(parents=True, exist_ok=True)
    out_tuned.parent.mkdir(parents=True, exist_ok=True)
    out_triptych.parent.mkdir(parents=True, exist_ok=True)

    analytic_raw.save(out_raw)
    analytic_tuned.save(out_tuned)
    _draw_triptych(out_path=out_triptych, baseline=baseline, analytic=analytic_raw, tuned=analytic_tuned)

    payload = {
        "input": {
            "source": str(src_path),
            "size": size,
            "baseline_sampling": "bilinear resize from extracted glow source cell",
        },
        "analytic_defaults": {
            "a": FIT_A,
            "b": FIT_B,
            "p": FIT_P,
            "c": FIT_C,
            "gain": FIT_GAIN,
            "rgb": list(FIT_RGB),
        },
        "raw_channel_stats": {
            k: {"mae": v.mae, "rmse": v.rmse, "bias": v.bias, "corr": v.corr}
            for k, v in raw_stats.items()
        },
        "fitted_rgb_from_unit_profile": {
            "r": tuned_rgb[0],
            "g": tuned_rgb[1],
            "b": tuned_rgb[2],
        },
        "tuned_channel_stats": {
            k: {"mae": v.mae, "rmse": v.rmse, "bias": v.bias, "corr": v.corr}
            for k, v in tuned_stats.items()
        },
        "artifacts": {
            "analytic_raw": str(out_raw),
            "analytic_tuned": str(out_tuned),
            "triptych": str(out_triptych),
        },
    }
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
