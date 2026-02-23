#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path("src").resolve()))

from crimson.render.projectile_draw.beam_sampling import build_beam_sample_plan
from crimson.views.beam_debug import (
    _ION_PRESET_ORDER,
    BeamDebugView,
    BeamIonPreset,
    BeamRenderMode,
    StampedVirtualHeadPass,
    _PreviewProjectile,
)
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext


def _unique_presets_by_type(presets: tuple[BeamIonPreset, ...]) -> tuple[BeamIonPreset, ...]:
    out: list[BeamIonPreset] = []
    seen: set[int] = set()
    for preset in presets:
        type_id = int(preset.projectile_type_id)
        if type_id in seen:
            continue
        seen.add(type_id)
        out.append(preset)
    return tuple(out)


def _draw_text(text: str, x: int, y: int, size: int, color: rl.Color) -> None:
    rl.draw_text(text.encode("utf-8"), int(x), int(y), int(size), color)


def _draw_text_centered(text: str, x: float, y: int, size: int, color: rl.Color) -> None:
    width = int(rl.measure_text(text.encode("utf-8"), int(size)))
    _draw_text(text, int(round(float(x) - float(width) * 0.5)), y, size, color)


def _build_preview(*, index: int, origin: Vec2, head: Vec2, life: float) -> _PreviewProjectile:
    dist_units = float((head - origin).length())
    plan = build_beam_sample_plan(dist=dist_units, step=2.48, max_span=256.0)
    return _PreviewProjectile(
        index=int(index),
        origin_screen=origin,
        head_screen=head,
        dist_units=float(dist_units),
        life=float(life),
        plan=plan,
    )


def _parse_mode(name: str) -> BeamRenderMode:
    for mode in BeamRenderMode:
        if mode.value == name:
            return mode
    available = ", ".join(sorted(m.value for m in BeamRenderMode))
    raise ValueError(f"unknown render mode '{name}', expected one of: {available}")


def _parse_stamped_virtual_head_pass(name: str) -> StampedVirtualHeadPass:
    for head_pass in StampedVirtualHeadPass:
        if head_pass.value == name:
            return head_pass
    available = ", ".join(sorted(v.value for v in StampedVirtualHeadPass))
    raise ValueError(f"unknown stamped-virtual head pass '{name}', expected one of: {available}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Render ion type comparison sheet with duplicate type ids removed.")
    parser.add_argument(
        "--mode",
        default=BeamRenderMode.SHADER_GEMINI_2.value,
        help="right-panel render mode value (e.g. shader_gemini_2, shader_stamped_virtual)",
    )
    parser.add_argument(
        "--out",
        default="artifacts/beam/ion_types_comparison_all_no_head_overlay.png",
        help="output PNG path",
    )
    parser.add_argument(
        "--head-pass",
        action="store_true",
        help="enable head pass (default: off)",
    )
    parser.add_argument(
        "--sv-head-pass",
        default=StampedVirtualHeadPass.VIRTUAL.value,
        help="stamped-virtual head pass when --mode=shader_stamped_virtual (virtual)",
    )
    parser.add_argument(
        "--sv-head-isolation",
        action="store_true",
        help="head-only isolation when --mode=shader_stamped_virtual",
    )
    parser.add_argument(
        "--sv-head-gain-scale",
        type=float,
        default=1.0,
        help="stamped-virtual head gain scale (default: 1.0)",
    )
    parser.add_argument(
        "--sv-head-radius-scale",
        type=float,
        default=1.0,
        help="stamped-virtual head radius scale (default: 1.0)",
    )
    args = parser.parse_args()

    mode = _parse_mode(str(args.mode))
    sv_head_pass = _parse_stamped_virtual_head_pass(str(args.sv_head_pass))
    out_path = Path(str(args.out))
    out_path.parent.mkdir(parents=True, exist_ok=True)

    presets = _unique_presets_by_type(_ION_PRESET_ORDER)
    if not presets:
        raise ValueError("ion preset list is empty after dedup")

    margin = 16
    header_h = 80
    row_h = 118
    left_label_w = 420
    panel_w = 500
    panel_gap = 24
    panel_beam_origin_x = 70.0
    panel_beam_len = 290.0
    life = 0.40

    width = margin * 2 + left_label_w + panel_w * 2 + panel_gap
    height = margin * 2 + header_h + row_h * len(presets)

    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.init_window(int(width), int(height), b"ion_type_preview")
    try:
        view = BeamDebugView(ViewContext(assets_dir=Path("artifacts/assets").resolve()))
        try:
            view.open()
            view._use_fire_profile = False
            view._head_render_enabled = bool(args.head_pass)
            view._show_geometry_overlay = False
            view._show_all_segment_markers = False
            view._stamped_virtual_head_pass = sv_head_pass
            view._stamped_virtual_head_isolation = bool(args.sv_head_isolation)
            view._stamped_virtual_head_gain_scale = float(args.sv_head_gain_scale)
            view._stamped_virtual_head_radius_scale = float(args.sv_head_radius_scale)

            preset_index_by_key = {preset.key: idx for idx, preset in enumerate(_ION_PRESET_ORDER)}

            target = rl.load_render_texture(int(width), int(height))
            rl.begin_texture_mode(target)
            rl.clear_background(rl.BLACK)

            head_status = "HEAD PASS ON" if bool(args.head_pass) else "HEAD PASS OFF"
            line_0 = f"ION PROJECTILE TYPE COMPARISON ({head_status})"
            line_1 = "left: BASELINE_SPRITE    right: selected shader mode"
            line_2 = (
                f"sv_head={sv_head_pass.value}  "
                f"sv_iso={'on' if bool(args.sv_head_isolation) else 'off'}  "
                f"sv_gain={float(args.sv_head_gain_scale):.2f}  "
                f"sv_radius={float(args.sv_head_radius_scale):.2f}"
            )
            _draw_text(line_0, margin, margin, 34, rl.Color(235, 245, 255, 255))
            _draw_text(line_1, margin, margin + 30, 24, rl.Color(150, 175, 210, 255))
            _draw_text(line_2, margin, margin + 54, 20, rl.Color(120, 150, 190, 255))

            left_panel_x = margin + left_label_w
            right_panel_x = left_panel_x + panel_w + panel_gap
            header_y = margin + header_h - 28
            _draw_text_centered("BASELINE_SPRITE", left_panel_x + panel_w * 0.5, header_y, 30, rl.Color(200, 220, 255, 255))
            _draw_text_centered(mode.value.upper(), right_panel_x + panel_w * 0.5, header_y, 30, rl.Color(200, 220, 255, 255))

            for row_idx, preset in enumerate(presets):
                preset_idx = preset_index_by_key.get(preset.key)
                if preset_idx is None:
                    continue
                view._ion_preset_index = int(preset_idx)
                view._sync_effect_scale()

                y_top = margin + header_h + row_idx * row_h
                y_mid = float(y_top + row_h // 2)

                label = f"{preset.label.upper()}  scale={view._effect_scale:.2f}  {preset.note}"
                _draw_text(label, margin, int(y_mid - 10.0), 28, rl.Color(230, 235, 245, 255))

                left_preview = _build_preview(
                    index=row_idx,
                    origin=Vec2(float(left_panel_x) + panel_beam_origin_x, y_mid),
                    head=Vec2(float(left_panel_x) + panel_beam_origin_x + panel_beam_len, y_mid),
                    life=life,
                )
                right_preview = _build_preview(
                    index=row_idx,
                    origin=Vec2(float(right_panel_x) + panel_beam_origin_x, y_mid),
                    head=Vec2(float(right_panel_x) + panel_beam_origin_x + panel_beam_len, y_mid),
                    life=life,
                )

                view._draw_projectiles([left_preview], mode=BeamRenderMode.BASELINE_SPRITE)
                view._draw_projectiles([right_preview], mode=mode)

                if row_idx + 1 < len(presets):
                    sep_y = int(y_top + row_h - 4)
                    rl.draw_line(margin, sep_y, width - margin, sep_y, rl.Color(30, 55, 85, 255))

            rl.end_texture_mode()

            image = rl.load_image_from_texture(target.texture)
            rl.image_flip_vertical(image)
            rl.export_image(image, str(out_path).encode("utf-8"))
            rl.unload_image(image)
            rl.unload_render_texture(target)
        finally:
            view.close()
    finally:
        rl.close_window()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
