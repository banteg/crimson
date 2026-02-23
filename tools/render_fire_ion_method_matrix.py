#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path("src").resolve()))

from crimson.render.projectile_draw.beam_sampling import build_beam_sample_plan
from crimson.views._ui_helpers import draw_ui_text
from crimson.views.beam_debug import (
    _ION_PRESET_ORDER,
    _RENDER_MODE_ORDER,
    BeamDebugView,
    BeamIonPreset,
    BeamRenderMode,
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


@dataclass(frozen=True, slots=True)
class MatrixRow:
    key: str
    label: str
    note: str
    ion_preset_key: str | None


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
        "--life",
        type=float,
        default=0.40,
        help="beam life used for all preview rows (default: 0.40)",
    )
    args = parser.parse_args()

    out_path = Path(str(args.out))
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = _rows()
    modes = tuple(_RENDER_MODE_ORDER)
    if not rows:
        raise ValueError("no rows to render")
    if not modes:
        raise ValueError("no render modes to render")

    heading_scale = 0.68
    pixel_scale = 1.0

    margin = 16
    header_h = 94
    row_h = 132
    row_label_w = 380
    cell_w = 280
    cell_gap = 18
    beam_origin_x = 34.0
    beam_len = 220.0

    width = margin * 2 + row_label_w + len(modes) * cell_w + max(0, len(modes) - 1) * cell_gap
    height = margin * 2 + header_h + len(rows) * row_h

    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.init_window(int(width), int(height), b"fire_ion_method_matrix")
    try:
        view = BeamDebugView(ViewContext(assets_dir=Path("artifacts/assets").resolve()))
        try:
            view.open()
            view._head_render_enabled = bool(args.head_pass)
            view._show_geometry_overlay = False
            view._show_all_segment_markers = False

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
                    margin - 2.0,
                    margin - 4.0,
                    heading_scale,
                    rl.Color(235, 245, 255, 255),
                )
                status = "HEAD PASS ON" if bool(args.head_pass) else "HEAD PASS OFF"
                subtitle = f"{HEADER_LINES[1]}  [{status}]"
                _draw_ui(
                    font,
                    subtitle,
                    margin,
                    margin + 28.0,
                    pixel_scale,
                    rl.Color(155, 180, 215, 255),
                )

                first_cell_x = margin + row_label_w
                col_header_y = margin + header_h - 22
                for col_idx, mode in enumerate(modes):
                    x = first_cell_x + col_idx * (cell_w + cell_gap)
                    _draw_ui_centered(
                        font,
                        mode.value.upper(),
                        x + cell_w * 0.5,
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

                    y_top = margin + header_h + row_idx * row_h
                    y_mid = float(y_top + row_h // 2)

                    row_label_y = y_mid - 18.0
                    row_meta_y = row_label_y + 18.0
                    row_meta = f"scale={view._effect_scale:.2f}  {row.note}"
                    _draw_ui(
                        font,
                        row.label,
                        margin,
                        row_label_y,
                        pixel_scale,
                        rl.Color(230, 235, 245, 255),
                    )
                    _draw_ui(
                        font,
                        row_meta,
                        margin,
                        row_meta_y,
                        pixel_scale,
                        rl.Color(155, 180, 215, 255),
                    )

                    step_units = float(view._beam_step_units())
                    for col_idx, mode in enumerate(modes):
                        x = first_cell_x + col_idx * (cell_w + cell_gap)
                        preview = _build_preview(
                            index=draw_index,
                            origin=Vec2(float(x) + beam_origin_x, y_mid),
                            head=Vec2(float(x) + beam_origin_x + beam_len, y_mid),
                            life=float(args.life),
                            step_units=step_units,
                            cap_enabled=bool(view._cap_enabled),
                        )
                        draw_index += 1
                        view._draw_projectiles([preview], mode=BeamRenderMode(mode))

                    if row_idx + 1 < len(rows):
                        sep_y = int(y_top + row_h - 4)
                        rl.draw_line(margin, sep_y, width - margin, sep_y, rl.Color(30, 55, 85, 255))

                rl.end_texture_mode()

                image = rl.load_image_from_texture(target.texture)
                rl.image_flip_vertical(image)
                rl.export_image(image, str(out_path).encode("utf-8"))
                rl.unload_image(image)
            finally:
                rl.unload_render_texture(target)
                if mono_font is not None:
                    rl.unload_texture(mono_font.texture)
        finally:
            view.close()
    finally:
        rl.close_window()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
