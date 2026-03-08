from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
import crimson.modes.quest_mode as quest_mode_module
from crimson.modes.quest_mode import QuestMode
from crimson.quests.level import QuestLevel
from grim.assets import RuntimeResources, TextureId, register_runtime_resources
from grim.fonts.small import SmallFontData
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext


def _register_runtime_resources_stub(assets_dir: Path) -> None:
    tex = cast("rl.Texture", SimpleNamespace(width=1, height=1, id=1))
    register_runtime_resources(
        RuntimeResources(
            assets_dir=assets_dir,
            textures={texture_id: tex for texture_id in TextureId},
            small_font=cast(SmallFontData, SimpleNamespace(cell_size=10, widths=[8] * 256)),
        ),
    )


def _make_quest_mode(mocker) -> QuestMode:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"
    _register_runtime_resources_stub(assets_dir)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = QuestMode(ctx, audio_rng=Crand(0xBEEF))
    mocker.patch.object(quest_mode_module, "load_grim_mono_font", return_value=SimpleNamespace())
    mode.open()
    mocker.patch.object(mode, "_sync_audio_and_ground", return_value=None)
    mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
    mode.start_run(QuestLevel(1, 1), status=None)
    mode.render_resources.ground = None
    return mode


def test_quest_mode_closes_run_when_player_dies_during_perk_menu_transition(monkeypatch, mocker) -> None:
    mode = _make_quest_mode(mocker)

    # Simulate Fatal Lottery killing the player while the perk menu is closing.
    # Quest mode should still produce a failure outcome after the native death-timer
    # delay instead of freezing.
    mode.player.health = -1.0
    mode.player.death_timer = 0.3
    mode._perk_menu.open = False
    mode._perk_menu.timeline_ms = 100.0

    mocker.patch.object(base_gameplay_mode_module.rl, "get_mouse_position", side_effect=lambda: rl.Vector2(0.0, 0.0))
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(quest_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    mode.update(1.0 / 60.0)

    assert mode.close_requested is False
    for _ in range(120):
        mode.update(1.0 / 60.0)
        if mode.close_requested:
            break
    assert mode.close_requested is True
    outcome = mode.consume_outcome()
    assert outcome is not None
    assert outcome.kind == "failed"
