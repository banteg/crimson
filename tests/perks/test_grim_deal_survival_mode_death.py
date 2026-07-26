from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
import crimson.modes.quest_mode as quest_mode_module
import crimson.modes.survival_mode as survival_mode_module
from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.quests.level import QuestLevel
from crimson.screens.results.game_over import GameOverUi
from grim.assets import RuntimeResources, TextureId, register_runtime_resources
from grim.fonts.small import SmallFontData
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def _register_runtime_resources_stub(assets_dir: Path) -> None:
    tex = cast("rl.Texture", SimpleNamespace(width=1, height=1, id=1))
    register_runtime_resources(
        RuntimeResources(
            assets_dir=assets_dir,
            textures={texture_id: tex for texture_id in TextureId},
            small_font=cast(SmallFontData, SimpleNamespace(cell_size=10, widths=[8] * 256)),
        ),
    )


def _is_dead(mode: SurvivalMode | QuestMode) -> bool:
    if isinstance(mode, SurvivalMode):
        return mode._game_over_active
    return mode._outcome is not None and mode._outcome.kind == "failed"


@pytest.mark.parametrize("mode_cls", [SurvivalMode, QuestMode])
def test_grim_deal_kills_player_during_perk_menu_transition(
    mocker,
    make_mode_config,
    mode_cls: type[SurvivalMode | QuestMode],
) -> None:
    assets_dir = _assets_dir()
    _register_runtime_resources_stub(assets_dir)
    ctx = ViewContext(assets_dir=assets_dir)
    game_mode = GameMode.SURVIVAL if mode_cls is SurvivalMode else GameMode.QUESTS
    mode = mode_cls(ctx, config=make_mode_config(game_mode=game_mode), audio_rng=Crand(0xBEEF))
    if isinstance(mode, QuestMode):
        mocker.patch.object(quest_mode_module, "load_grim_mono_font", return_value=SimpleNamespace())
        mode.open()
        mocker.patch.object(mode, "_sync_audio_and_ground", return_value=None)
        mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
        mode.start_run(QuestLevel(1, 1), status=None)
        mode.render_resources.ground = None
    else:
        mode.open()
        mocker.patch.object(mode, "_sync_audio_and_ground", return_value=None)
    mocker.patch.object(GameOverUi, "open", return_value=None)

    assert mode.player.health > 0.0
    mode.player.death_timer = 0.3
    mode._perk_menu.open = True
    mode._perk_menu.timeline_ms = 100.0

    def _apply_grim_deal_and_close(_ctx, _choices, *, dt_ui_ms: float) -> None:
        perk_apply(mode.state, mode.sim_world.players, PerkId.GRIM_DEAL)
        mode._perk_menu.close()

    mocker.patch.object(mode._perk_menu, "handle_input", side_effect=_apply_grim_deal_and_close)

    mocker.patch.object(base_gameplay_mode_module.rl, "get_mouse_position", side_effect=lambda: rl.Vector2(0.0, 0.0))
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(survival_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)
    mocker.patch.object(quest_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    mode.update(1.0 / 60.0)

    assert mode.player.health < 0.0
    assert not _is_dead(mode)
    for _ in range(10):
        mode.update(1.0 / 60.0)
    assert _is_dead(mode)
