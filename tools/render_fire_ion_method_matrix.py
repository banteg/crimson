#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path("src").resolve()))

from PIL import Image, ImageDraw

from crimson.render.projectile_draw.beam_sampling import build_beam_sample_plan
from crimson.views._ui_helpers import draw_ui_text
from crimson.views.beam_debug import (
    _ION_PRESET_ORDER,
    BeamDebugView,
    BeamIonPreset,
    BeamRenderMode,
    StampedVirtualHeadPass,
    _PreviewProjectile,
)
from grim.fonts.grim_mono import GrimMonoFont, draw_grim_mono_text, load_grim_mono_font
from grim.fonts.small import SmallFontData, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext

HEADER_LINES: Final[tuple[str, str]] = (
    "FIRE + ION PROJECTILES ACROSS ALL BEAM METHODS",
    "rows: fire bullets + ion type ids (dedup)   cols: render methods",
)

SIGNED_NEGATIVE_STOPS: Final[tuple[tuple[float, tuple[int, int, int]], ...]] = (
    (0.0, (0, 0, 0)),
    (0.35, (20, 40, 120)),
    (0.70, (20, 140, 240)),
    (1.0, (200, 255, 255)),
)

SIGNED_POSITIVE_STOPS: Final[tuple[tuple[float, tuple[int, int, int]], ...]] = (
    (0.0, (0, 0, 0)),
    (0.35, (120, 35, 10)),
    (0.70, (255, 140, 20)),
    (1.0, (255, 245, 140)),
)

LUMA_WEIGHT_K: Final[float] = 2.0


@dataclass(frozen=True, slots=True)
class MatrixRow:
    key: str
    label: str
    note: str
    ion_preset_key: str | None


@dataclass(frozen=True, slots=True)
class MatrixLayout:
    margin: int
    header_h: int
    row_h: int
    row_label_w: int
    cell_w: int
    cell_gap: int


@dataclass(frozen=True, slots=True)
class MatrixColumn:
    label: str
    mode: BeamRenderMode
    stamped_virtual_head_pass: StampedVirtualHeadPass | None = None
    stamped_virtual_head_isolation: bool = False


def _clamp01(value: float) -> float:
    if value <= 0.0:
        return 0.0
    if value >= 1.0:
        return 1.0
    return value


def _lerp_u8(a: int, b: int, t: float) -> int:
    out = float(a) * (1.0 - t) + float(b) * t
    return max(0, min(255, int(round(out))))


def _sample_stops(stops: tuple[tuple[float, tuple[int, int, int]], ...], t: float) -> tuple[int, int, int]:
    t = _clamp01(t)
    if t <= float(stops[0][0]):
        return stops[0][1]
    if t >= float(stops[-1][0]):
        return stops[-1][1]
    for idx in range(1, len(stops)):
        left_pos, left_color = stops[idx - 1]
        right_pos, right_color = stops[idx]
        if t <= float(right_pos):
            span = max(1e-9, float(right_pos) - float(left_pos))
            local_t = (float(t) - float(left_pos)) / span
            return (
                _lerp_u8(left_color[0], right_color[0], local_t),
                _lerp_u8(left_color[1], right_color[1], local_t),
                _lerp_u8(left_color[2], right_color[2], local_t),
            )
    return stops[-1][1]


def _beam_luma(px: tuple[int, int, int]) -> int:
    return max(int(px[0]), int(px[1]), int(px[2]))


def _text_width(font: SmallFontData | None, text: str, scale: float) -> float:
    if font is not None:
        return float(measure_small_text_width(font, text, scale))
    return float(rl.measure_text(text.encode("utf-8"), int(20 * float(scale))))


def _draw_ui(font: SmallFontData | None, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
    draw_ui_text(font, text, Vec2(float(x), float(y)), color=color, scale=float(scale))


def _draw_ui_centered(
    font: SmallFontData | None,
    text: str,
    center_x: float,
    y: float,
    scale: float,
    color: rl.Color,
) -> None:
    width = _text_width(font, text, scale)
    _draw_ui(font, text, float(center_x) - width * 0.5, y, scale, color)


def _draw_heading(font: GrimMonoFont | None, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
    if font is not None:
        draw_grim_mono_text(font, text, Vec2(float(x), float(y)), float(scale), color)
        return
    rl.draw_text(text.encode("utf-8"), int(x), int(y), 24, color)


def _unique_ion_presets_by_type(presets: tuple[BeamIonPreset, ...]) -> tuple[BeamIonPreset, ...]:
    out: list[BeamIonPreset] = []
    seen: set[int] = set()
    for preset in presets:
        type_id = int(preset.projectile_type_id)
        if type_id in seen:
            continue
        seen.add(type_id)
        out.append(preset)
    return tuple(out)


def _build_preview(
    *,
    index: int,
    origin: Vec2,
    head: Vec2,
    life: float,
    step_units: float,
    cap_enabled: bool,
) -> _PreviewProjectile:
    dist_units = float((head - origin).length())
    max_span = 256.0 if bool(cap_enabled) else dist_units
    plan = build_beam_sample_plan(dist=dist_units, step=float(step_units), max_span=max_span)
    return _PreviewProjectile(
        index=int(index),
        origin_screen=origin,
        head_screen=head,
        dist_units=float(dist_units),
        life=float(life),
        plan=plan,
    )


def _rows() -> tuple[MatrixRow, ...]:
    ion_rows = tuple(
        MatrixRow(
            key=f"ion_{preset.key}",
            label=preset.label.upper(),
            note=preset.note,
            ion_preset_key=preset.key,
        )
        for preset in _unique_ion_presets_by_type(_ION_PRESET_ORDER)
    )
    return (
        MatrixRow(
            key="fire_bullets",
            label="FIRE BULLETS",
            note="type=fire",
            ion_preset_key=None,
        ),
        *ion_rows,
    )


def _columns() -> tuple[MatrixColumn, ...]:
    return (
        MatrixColumn(label=BeamRenderMode.BASELINE_SPRITE.value.upper(), mode=BeamRenderMode.BASELINE_SPRITE),
        MatrixColumn(
            label="SV+HEAD_ANALYTIC",
            mode=BeamRenderMode.SHADER_STAMPED_VIRTUAL,
            stamped_virtual_head_pass=StampedVirtualHeadPass.ANALYTIC,
            stamped_virtual_head_isolation=False,
        ),
        MatrixColumn(
            label="SV+HEAD_VIRTUAL",
            mode=BeamRenderMode.SHADER_STAMPED_VIRTUAL,
            stamped_virtual_head_pass=StampedVirtualHeadPass.VIRTUAL,
            stamped_virtual_head_isolation=False,
        ),
        MatrixColumn(
            label="SV+HEAD_VIRTUAL_ISO",
            mode=BeamRenderMode.SHADER_STAMPED_VIRTUAL,
            stamped_virtual_head_pass=StampedVirtualHeadPass.VIRTUAL,
            stamped_virtual_head_isolation=True,
        ),
        MatrixColumn(label=BeamRenderMode.SHADER_EXT_GPT_PRO.value.upper(), mode=BeamRenderMode.SHADER_EXT_GPT_PRO),
        MatrixColumn(label=BeamRenderMode.SHADER_GEMINI_2.value.upper(), mode=BeamRenderMode.SHADER_GEMINI_2),
    )


def _signed_diff_map(
    *,
    baseline: Image.Image,
    candidate: Image.Image,
    signed_clip: float,
    neutral_band: float,
) -> tuple[Image.Image, float, float, float, float]:
    width, height = baseline.size
    if candidate.size != baseline.size:
        raise ValueError("baseline/candidate image sizes differ for signed diff")

    baseline_bytes = baseline.tobytes()
    candidate_bytes = candidate.tobytes()
    signed_pixels: list[tuple[int, int, int]] = []

    signed_den = max(1e-6, float(signed_clip) * 255.0)
    neutral = max(0.0, float(neutral_band) * 255.0)

    abs_sum = 0.0
    weighted_abs_sum = 0.0
    weighted_total = 0.0
    under_sum = 0.0
    over_sum = 0.0
    pixel_count = width * height
    for pixel_idx in range(pixel_count):
        offset = pixel_idx * 3
        base_l = _beam_luma(
            (
                int(baseline_bytes[offset + 0]),
                int(baseline_bytes[offset + 1]),
                int(baseline_bytes[offset + 2]),
            ),
        )
        cand_l = _beam_luma(
            (
                int(candidate_bytes[offset + 0]),
                int(candidate_bytes[offset + 1]),
                int(candidate_bytes[offset + 2]),
            ),
        )
        diff = int(cand_l) - int(base_l)
        abs_diff = abs(diff)
        abs_sum += float(abs_diff)
        weight = 1.0 + float(LUMA_WEIGHT_K) * (float(base_l) / 255.0)
        weighted_abs_sum += float(abs_diff) * weight
        weighted_total += weight
        if diff < 0:
            under_sum += float(-diff)
        elif diff > 0:
            over_sum += float(diff)

        if float(abs_diff) <= neutral:
            signed_pixels.append((0, 0, 0))
            continue
        t = _clamp01(float(abs_diff) / signed_den)
        if diff > 0:
            signed_pixels.append(_sample_stops(SIGNED_POSITIVE_STOPS, t))
        else:
            signed_pixels.append(_sample_stops(SIGNED_NEGATIVE_STOPS, t))

    signed = Image.new("RGB", baseline.size)
    signed.putdata(signed_pixels)

    total = max(1.0, float(width * height * 255))
    return (
        signed,
        float(abs_sum / total),
        float(weighted_abs_sum / max(1e-9, weighted_total * 255.0)),
        float(under_sum / total),
        float(over_sum / total),
    )


def _build_signed_diff_vstack(
    *,
    row: MatrixRow,
    panels: list[tuple[str, Image.Image, float, float, float, float]],
) -> Image.Image:
    if not panels:
        raise ValueError("no panels for signed diff vstack")
    panel_w = panels[0][1].width
    panel_h = panels[0][1].height
    margin = 16
    left_w = 380
    title_h = 44
    row_gap = 12
    item_h = panel_h + 22
    width = margin * 2 + left_w + panel_w
    height = margin * 2 + title_h + len(panels) * item_h + max(0, len(panels) - 1) * row_gap
    canvas = Image.new("RGB", (width, height), (0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    title = f"{row.label}  ({row.note})"
    draw.text((margin, margin), title, fill=(235, 245, 255))
    draw.text((margin, margin + 16), "signed diff: cyan=baseline brighter, orange=candidate brighter", fill=(155, 180, 215))

    y = margin + title_h
    for mode_label, panel, mae, wmae, under, over in panels:
        draw.text((margin, y + 3), mode_label, fill=(215, 225, 240))
        draw.text(
            (margin, y + 15),
            f"mae={mae:.4f} wmae={wmae:.4f} under={under:.4f} over={over:.4f}",
            fill=(135, 165, 205),
        )
        canvas.paste(panel, (margin + left_w, y))
        y += item_h + row_gap
    return canvas


def _export_signed_diff_vstacks(
    *,
    matrix_path: Path,
    rows: tuple[MatrixRow, ...],
    columns: tuple[MatrixColumn, ...],
    layout: MatrixLayout,
    out_dir: Path,
    signed_clip: float,
    neutral_band: float,
) -> None:
    if len(columns) < 2:
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    matrix = Image.open(matrix_path).convert("RGB")
    first_cell_x = int(layout.margin + layout.row_label_w)
    for row_idx, row in enumerate(rows):
        y0 = int(layout.margin + layout.header_h + row_idx * layout.row_h)
        baseline_cell = matrix.crop(
            (
                first_cell_x,
                y0,
                first_cell_x + int(layout.cell_w),
                y0 + int(layout.row_h),
            ),
        )
        panels: list[tuple[str, Image.Image, float, float, float, float]] = []
        for col_idx, column in enumerate(columns):
            if col_idx == 0:
                continue
            x0 = int(first_cell_x + col_idx * (layout.cell_w + layout.cell_gap))
            candidate_cell = matrix.crop((x0, y0, x0 + int(layout.cell_w), y0 + int(layout.row_h)))
            signed_map, mae, wmae, under, over = _signed_diff_map(
                baseline=baseline_cell,
                candidate=candidate_cell,
                signed_clip=float(signed_clip),
                neutral_band=float(neutral_band),
            )
            panels.append(
                (
                    column.label,
                    signed_map,
                    float(mae),
                    float(wmae),
                    float(under),
                    float(over),
                ),
            )

        sheet = _build_signed_diff_vstack(row=row, panels=panels)
        out_path = out_dir / f"{row_idx:02d}_{row.key}_signed_diff_vstack.png"
        sheet.save(out_path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a comparison matrix: fire + ion projectile rows versus all beam render methods.",
    )
    parser.add_argument(
        "--out",
        default="artifacts/beam/fire_ion_all_methods_matrix_no_head_overlay.png",
        help="output PNG path",
    )
    parser.add_argument(
        "--head-pass",
        action="store_true",
        help="enable head pass (default: off)",
    )
    parser.add_argument(
        "--sv-head-gain-scale",
        type=float,
        default=1.0,
        help="stamped-virtual head gain scale for virtual-head columns (default: 1.0)",
    )
    parser.add_argument(
        "--sv-head-radius-scale",
        type=float,
        default=1.0,
        help="stamped-virtual head radius scale for virtual-head columns (default: 1.0)",
    )
    parser.add_argument(
        "--life",
        type=float,
        default=0.40,
        help="beam life used for all preview rows (default: 0.40)",
    )
    parser.add_argument(
        "--signed-diff-vstack-dir",
        default="artifacts/beam/fire_ion_all_methods_signed_diff_vstack",
        help="output dir for per-row vertical signed-diff sheets",
    )
    parser.add_argument(
        "--skip-signed-diff-vstack",
        action="store_true",
        help="skip exporting per-row signed-diff vstack images",
    )
    parser.add_argument(
        "--signed-diff-clip",
        type=float,
        default=0.35,
        help="signed diff saturation (0..1, default: 0.35)",
    )
    parser.add_argument(
        "--signed-diff-neutral-band",
        type=float,
        default=0.01,
        help="signed diff deadband near zero (0..1, default: 0.01)",
    )
    args = parser.parse_args()

    out_path = Path(str(args.out))
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = _rows()
    columns = _columns()
    if not rows:
        raise ValueError("no rows to render")
    if not columns:
        raise ValueError("no render modes to render")

    heading_scale = 0.68
    pixel_scale = 1.0

    layout = MatrixLayout(
        margin=16,
        header_h=94,
        row_h=132,
        row_label_w=380,
        cell_w=280,
        cell_gap=18,
    )
    beam_origin_x = 34.0
    beam_len = 220.0

    width = (
        layout.margin * 2
        + layout.row_label_w
        + len(columns) * layout.cell_w
        + max(0, len(columns) - 1) * layout.cell_gap
    )
    height = layout.margin * 2 + layout.header_h + len(rows) * layout.row_h

    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.init_window(int(width), int(height), b"fire_ion_method_matrix")
    try:
        view = BeamDebugView(ViewContext(assets_dir=Path("artifacts/assets").resolve()))
        try:
            view.open()
            view._head_render_enabled = bool(args.head_pass)
            view._show_geometry_overlay = False
            view._show_all_segment_markers = False
            view._stamped_virtual_head_gain_scale = float(args.sv_head_gain_scale)
            view._stamped_virtual_head_radius_scale = float(args.sv_head_radius_scale)

            mono_font: GrimMonoFont | None
            try:
                mono_font = load_grim_mono_font(view._assets_root)
            except FileNotFoundError:
                mono_font = None

            preset_index_by_key = {preset.key: idx for idx, preset in enumerate(_ION_PRESET_ORDER)}

            target = rl.load_render_texture(int(width), int(height))
            try:
                rl.begin_texture_mode(target)
                rl.clear_background(rl.BLACK)

                font = view._small
                _draw_heading(
                    mono_font,
                    HEADER_LINES[0],
                    layout.margin - 2.0,
                    layout.margin - 4.0,
                    heading_scale,
                    rl.Color(235, 245, 255, 255),
                )
                status = "HEAD PASS ON" if bool(args.head_pass) else "HEAD PASS OFF"
                subtitle = (
                    f"{HEADER_LINES[1]}  [{status}]  "
                    f"[sv_head_gain={float(args.sv_head_gain_scale):.2f} sv_head_radius={float(args.sv_head_radius_scale):.2f}]"
                )
                _draw_ui(
                    font,
                    subtitle,
                    layout.margin,
                    layout.margin + 28.0,
                    pixel_scale,
                    rl.Color(155, 180, 215, 255),
                )

                first_cell_x = layout.margin + layout.row_label_w
                col_header_y = layout.margin + layout.header_h - 22
                for col_idx, column in enumerate(columns):
                    x = first_cell_x + col_idx * (layout.cell_w + layout.cell_gap)
                    _draw_ui_centered(
                        font,
                        column.label,
                        x + layout.cell_w * 0.5,
                        col_header_y,
                        pixel_scale,
                        rl.Color(200, 220, 255, 255),
                    )

                draw_index = 0
                for row_idx, row in enumerate(rows):
                    if row.ion_preset_key is None:
                        view._use_fire_profile = True
                    else:
                        view._use_fire_profile = False
                        preset_idx = preset_index_by_key.get(row.ion_preset_key)
                        if preset_idx is not None:
                            view._ion_preset_index = int(preset_idx)
                    view._sync_effect_scale()

                    y_top = layout.margin + layout.header_h + row_idx * layout.row_h
                    y_mid = float(y_top + layout.row_h // 2)

                    row_label_y = y_mid - 18.0
                    row_meta_y = row_label_y + 18.0
                    row_meta = f"scale={view._effect_scale:.2f}  {row.note}"
                    _draw_ui(
                        font,
                        row.label,
                        layout.margin,
                        row_label_y,
                        pixel_scale,
                        rl.Color(230, 235, 245, 255),
                    )
                    _draw_ui(
                        font,
                        row_meta,
                        layout.margin,
                        row_meta_y,
                        pixel_scale,
                        rl.Color(155, 180, 215, 255),
                    )

                    step_units = float(view._beam_step_units())
                    for col_idx, column in enumerate(columns):
                        x = first_cell_x + col_idx * (layout.cell_w + layout.cell_gap)
                        if column.mode == BeamRenderMode.SHADER_STAMPED_VIRTUAL:
                            if column.stamped_virtual_head_pass is not None:
                                view._stamped_virtual_head_pass = column.stamped_virtual_head_pass
                            view._stamped_virtual_head_isolation = bool(column.stamped_virtual_head_isolation)
                        else:
                            view._stamped_virtual_head_pass = StampedVirtualHeadPass.ANALYTIC
                            view._stamped_virtual_head_isolation = False
                        preview = _build_preview(
                            index=draw_index,
                            origin=Vec2(float(x) + beam_origin_x, y_mid),
                            head=Vec2(float(x) + beam_origin_x + beam_len, y_mid),
                            life=float(args.life),
                            step_units=step_units,
                            cap_enabled=bool(view._cap_enabled),
                        )
                        draw_index += 1
                        view._draw_projectiles([preview], mode=BeamRenderMode(column.mode))

                    if row_idx + 1 < len(rows):
                        sep_y = int(y_top + layout.row_h - 4)
                        rl.draw_line(layout.margin, sep_y, width - layout.margin, sep_y, rl.Color(30, 55, 85, 255))

                rl.end_texture_mode()

                image = rl.load_image_from_texture(target.texture)
                rl.image_flip_vertical(image)
                rl.export_image(image, str(out_path).encode("utf-8"))
                rl.unload_image(image)
            finally:
                rl.unload_render_texture(target)
                if mono_font is not None:
                    rl.unload_texture(mono_font.texture)

            if not bool(args.skip_signed_diff_vstack):
                _export_signed_diff_vstacks(
                    matrix_path=out_path,
                    rows=rows,
                    columns=columns,
                    layout=layout,
                    out_dir=Path(str(args.signed_diff_vstack_dir)),
                    signed_clip=float(args.signed_diff_clip),
                    neutral_band=float(args.signed_diff_neutral_band),
                )
        finally:
            view.close()
    finally:
        rl.close_window()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
