from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pyray as rl

from crimson.game_world import GameWorld
from crimson.modes.survival_mode import SurvivalMode
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from grim.view import ViewContext


def _make_survival_mode() -> SurvivalMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    return SurvivalMode(ctx)


def _install_minimal_sim_session(mode: SurvivalMode, monkeypatch) -> None:
    class _FakeSession:
        def __init__(self) -> None:
            self.game_tune_started = False
            self.elapsed_ms = 0.0
            self.stage = 0
            self.spawn_cooldown_ms = 0.0
            self.detail_preset = 5
            self.fx_toggle = 0

        def step_tick(self, *, dt_frame: float, inputs):  # noqa: ANN001
            _ = inputs
            self.elapsed_ms += float(dt_frame) * 1000.0
            for player in mode._world.players:
                if float(player.health) <= 0.0:
                    player.death_timer -= float(dt_frame) * 20.0
            step = SimpleNamespace(events=SimpleNamespace(deaths=()), command_hash=0)
            return SimpleNamespace(step=step, rng_marks={})

    mode._sim_session = _FakeSession()
    monkeypatch.setattr(GameWorld, "apply_step_result", lambda *_args, **_kwargs: None)


def test_survival_mode_enters_game_over_when_grim_deal_kills_player_during_perk_menu_transition(monkeypatch) -> None:
    mode = _make_survival_mode()
    monkeypatch.setattr("crimson.ui.game_over.GameOverUi.open", lambda self: None)  # noqa: ARG005
    _install_minimal_sim_session(mode, monkeypatch)

    assert mode._player.health > 0.0
    mode._player.death_timer = 0.3
    mode._perk_menu.open = True
    mode._perk_menu.timeline_ms = 100.0

    def _apply_grim_deal_and_close(_ctx, *, dt_frame: float, dt_ui_ms: float) -> None:
        perk_apply(mode.state, mode._world.players, PerkId.GRIM_DEAL)
        mode._perk_menu.close()

    monkeypatch.setattr(mode._perk_menu, "handle_input", _apply_grim_deal_and_close)

    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_mouse_position", lambda: rl.Vector2(0.0, 0.0))
    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.is_key_pressed", lambda _key: False)

    mode.update(1.0 / 60.0)

    assert mode._player.health < 0.0
    assert mode._game_over_active is False
    for _ in range(120):
        mode.update(1.0 / 60.0)
        if mode._game_over_active:
            break
    assert mode._game_over_active is True
