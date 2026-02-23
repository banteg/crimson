import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path("src").resolve()))
from crimson.render.projectile_draw.beam_sampling import build_beam_sample_plan
from crimson.views.beam_debug import BeamDebugView, BeamRenderMode, StampedVirtualHeadPass
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext


class HackView(BeamDebugView):
    def update(self, dt):
        return

    def _draw_overlay(self, *args, **kwargs):
        return


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


def main():
    parser = argparse.ArgumentParser(description="Render stacked beam comparison rows.")
    parser.add_argument("--top-mode", default=BeamRenderMode.BASELINE_SPRITE.value)
    parser.add_argument("--bottom-mode", default=BeamRenderMode.SHADER_GEMINI_2.value)
    parser.add_argument("--head-pass", action="store_true", help="enable head pass (default: off)")
    parser.add_argument("--sv-head-pass", default=StampedVirtualHeadPass.ANALYTIC.value)
    parser.add_argument("--sv-head-isolation", action="store_true")
    parser.add_argument("--sv-head-gain-scale", type=float, default=1.0)
    parser.add_argument("--sv-head-radius-scale", type=float, default=1.0)
    parser.add_argument("--out", default="artifacts/beam/comparison_horizontal_stacked.png")
    args = parser.parse_args()

    top_mode = _parse_mode(str(args.top_mode))
    bottom_mode = _parse_mode(str(args.bottom_mode))
    sv_head_pass = _parse_stamped_virtual_head_pass(str(args.sv_head_pass))

    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.init_window(1280, 240, b'Hidden')

    ctx = ViewContext(assets_dir=Path("artifacts/assets").resolve())
    view = HackView(ctx)
    try:
        view.open()
    except Exception:
        pass

    view._head_render_enabled = bool(args.head_pass)
    view._stamped_virtual_head_pass = sv_head_pass
    view._stamped_virtual_head_isolation = bool(args.sv_head_isolation)
    view._stamped_virtual_head_gain_scale = float(args.sv_head_gain_scale)
    view._stamped_virtual_head_radius_scale = float(args.sv_head_radius_scale)

    target = rl.load_render_texture(1280, 240)
    rl.begin_texture_mode(target)
    rl.clear_background(rl.BLACK)

    y_center = 120.0
    from crimson.views.beam_debug import _PreviewProjectile

    def mk_preview(idx, y_offset, life_val=0.4):
        dist = 800.0
        plan = build_beam_sample_plan(dist=dist, step=2.48, max_span=256.0)
        return _PreviewProjectile(
            index=idx,
            origin_screen=Vec2(200.0, y_center + y_offset),
            head_screen=Vec2(200.0 + dist, y_center + y_offset),
            dist_units=dist,
            life=life_val,
            plan=plan,
        )

    p1 = [mk_preview(0, -30.0)]
    p2 = [mk_preview(1, 50.0)]

    view._draw_projectiles(p1, mode=top_mode)
    view._draw_projectiles(p2, mode=bottom_mode)

    rl.draw_text(top_mode.value.upper().encode("utf-8"), 20, int(y_center - 30.0 - 10), 20, rl.WHITE)
    rl.draw_text(bottom_mode.value.upper().encode("utf-8"), 20, int(y_center + 50.0 - 10), 20, rl.WHITE)

    rl.end_texture_mode()

    image = rl.load_image_from_texture(target.texture)
    rl.image_flip_vertical(image)
    rl.export_image(image, str(args.out).encode("utf-8"))
    rl.unload_image(image)
    rl.unload_render_texture(target)

    view.close()
    rl.close_window()


if __name__ == "__main__":
    main()
