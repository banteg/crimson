import argparse
import sys
from pathlib import Path

# ensure we can import crimson
sys.path.insert(0, str(Path("src").resolve()))

from crimson.views.beam_debug import BeamDebugView, BeamRenderMode, BeamScenarioPreset, StampedVirtualHeadPass
from grim.raylib_api import rl
from grim.view import ViewContext


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
    parser = argparse.ArgumentParser(description="Render side-by-side beam comparison screenshot.")
    parser.add_argument("--mode", default=BeamRenderMode.SHADER_GEMINI_2.value)
    parser.add_argument("--head-pass", action="store_true", help="enable head pass (default: off)")
    parser.add_argument("--sv-head-pass", default=StampedVirtualHeadPass.ANALYTIC.value)
    parser.add_argument("--sv-head-isolation", action="store_true")
    parser.add_argument("--sv-head-gain-scale", type=float, default=1.0)
    parser.add_argument("--sv-head-radius-scale", type=float, default=1.0)
    parser.add_argument("--out", default="artifacts/beam/comparison_no_glow.png")
    args = parser.parse_args()

    mode = _parse_mode(str(args.mode))
    sv_head_pass = _parse_stamped_virtual_head_pass(str(args.sv_head_pass))

    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.init_window(1280, 800, b'Hidden')

    # Assets dir needs to be pointing to something that lets the textures load. 
    # Usually in crimson we run from project root, so let's try artifacts/assets 
    # or the default paths in `resolve_beam_debug_assets_root`.
    
    # We can try to use a view
    ctx = ViewContext(assets_dir=Path("artifacts/assets").resolve())
    view = BeamDebugView(ctx)
    try:
        view.open()
    except Exception as e:
        print(f"could not load assets: {e}")
        # Try finding paq or standard paths
        pass

    view.apply_scenario_preset(BeamScenarioPreset.PLASMA_LIKE)
    view._side_by_side_enabled = True
    view._bench_active = False
    
    # "without the additional head glow pass"
    view._head_render_enabled = bool(args.head_pass)
    view._stamped_virtual_head_pass = sv_head_pass
    view._stamped_virtual_head_isolation = bool(args.sv_head_isolation)
    view._stamped_virtual_head_gain_scale = float(args.sv_head_gain_scale)
    view._stamped_virtual_head_radius_scale = float(args.sv_head_radius_scale)

    for _ in range(4):
        view.update(1.0 / 60.0)
    
    view._render_mode = mode

    target = rl.load_render_texture(1280, 800)
    rl.begin_texture_mode(target)
    view.draw()
    rl.end_texture_mode()

    image = rl.load_image_from_texture(target.texture)
    rl.image_flip_vertical(image)
    rl.export_image(image, str(args.out).encode("utf-8"))
    rl.unload_image(image)
    rl.unload_render_texture(target)

    view.close()
    rl.close_window()

if __name__ == '__main__':
    main()
