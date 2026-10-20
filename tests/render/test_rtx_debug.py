from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from crimson.render.rtx.debug import RtxDebugView, debug_hotkey
from crimson.render.rtx.mode import RtxRenderMode
from crimson.world import runtime as runtime_module
from grim.raylib_api import rl
from tests.support.world_runtime import WorldRuntimeHost


def test_debug_hotkey_cycles_both_directions_without_touching_game_state(mocker):
    mocker.patch.object(rl, "is_key_pressed", return_value=True)
    held = mocker.patch.object(rl, "is_key_down", return_value=False)
    assert debug_hotkey(RtxDebugView.SHADED) is RtxDebugView.SUBSTRATE_NORMAL
    held.return_value = True
    assert debug_hotkey(RtxDebugView.SHADED) is RtxDebugView.NO_DIRECT
    assert RtxDebugView.parse("direct-unshadowed") is RtxDebugView.DIRECT_UNSHADOWED


def test_diagnostics_bypass_hdr_but_classic_ignores_selection(assets_dir, mocker):
    runtime = WorldRuntimeHost(assets_dir=assets_dir)
    mocker.patch.object(type(runtime.render_resources), "process_ground_pending")
    context = SimpleNamespace(view=SimpleNamespace(out_size=None))
    mocker.patch.object(runtime, "_render_ctx", return_value=context)
    draw = mocker.patch.object(runtime_module, "draw_world")
    label = mocker.patch.object(runtime_module, "draw_debug_label")
    scopes = []

    @contextmanager
    def scope(*, out_size):
        scopes.append(out_size)
        yield

    mocker.patch.object(type(runtime.render_resources.hdr), "scope", side_effect=scope)
    runtime.rtx_debug = RtxDebugView.SUBSTRATE_NORMAL
    runtime.draw()
    assert not runtime.rtx_debug_active
    assert not scopes
    label.assert_not_called()
    runtime.rtx_mode = RtxRenderMode.RTX
    runtime.draw()
    assert runtime.rtx_debug_active
    assert not scopes
    label.assert_called_once_with(RtxDebugView.SUBSTRATE_NORMAL)
    runtime.rtx_debug = RtxDebugView.SHADED
    runtime.draw()
    assert scopes == [None]
    runtime.rtx_debug = RtxDebugView.NO_DIRECT
    runtime.draw()
    assert scopes == [None, None]
    assert not runtime.rtx_debug_map_active
    assert draw.call_count == 4
