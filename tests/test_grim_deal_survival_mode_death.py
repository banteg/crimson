from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
import crimson.modes.survival_mode as survival_mode_module
from crimson.modes.survival_mode import SurvivalMode
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.sessions import DeterministicSession
from crimson.sim.timing import FrameTiming
from crimson.sim.world_state import WorldEvents
from crimson.ui.game_over import GameOverUi
from grim.raylib_api import rl
from grim.view import ViewContext


def _make_survival_mode(
    *,
    session_factory: Callable[..., DeterministicSession] | None = None,
) -> SurvivalMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    if session_factory is None:
        return SurvivalMode(ctx)
    return SurvivalMode(ctx, session_factory=session_factory)


def _install_minimal_sim_session(mocker) -> Callable[..., DeterministicSession]:
    class _FakeSession:
        def __init__(self, *, world) -> None:
            self._world = world
            self.game_tune_started = False
            self.elapsed_ms = 0.0
            self.stage = 0
            self.spawn_cooldown_ms = 0.0
            self.detail_preset = 5
            self.gore_disabled = 0

        def timing_for_dt(self, dt: float) -> FrameTiming:
            return FrameTiming.compute(
                float(dt),
                time_scale_active_entry=False,
                time_scale_factor=1.0,
                zero_gate_active=False,
            )

        def step_tick(self, *, timing: FrameTiming, inputs, trace_rng: bool = False):
            _ = inputs
            _ = trace_rng
            dt = float(timing.dt)
            self.elapsed_ms += float(dt) * 1000.0
            for player in self._world.players:
                if float(player.health) <= 0.0:
                    player.death_timer -= float(dt) * 20.0
            step = SimpleNamespace(
                events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
                command_hash="0",
                dt_sim=float(dt),
                presentation=None,
                presentation_plan_ms=0.0,
            )
            return SimpleNamespace(
                step=step,
                command_hash="0",
                dt_sim=float(dt),
                presentation_plan_ms=0.0,
                rng_marks={},
                elapsed_ms=float(self.elapsed_ms),
                creature_count_world_step=0,
            )

    return lambda *, world, **_kwargs: cast(DeterministicSession, _FakeSession(world=world))


def test_survival_mode_enters_game_over_when_grim_deal_kills_player_during_perk_menu_transition(mocker) -> None:
    session_factory = _install_minimal_sim_session(mocker)
    mode = _make_survival_mode(session_factory=session_factory)
    mocker.patch.object(GameOverUi, "open", return_value=None)

    assert mode.player.health > 0.0
    mode.player.death_timer = 0.3
    mode._perk_menu.open = True
    mode._perk_menu.timeline_ms = 100.0

    def _apply_grim_deal_and_close(_ctx, *, dt: float, dt_ui_ms: float) -> None:
        perk_apply(mode.state, mode.sim_world.players, PerkId.GRIM_DEAL)
        mode._perk_menu.close()

    mocker.patch.object(mode._perk_menu, "handle_input", side_effect=_apply_grim_deal_and_close)

    mocker.patch.object(base_gameplay_mode_module.rl, "get_mouse_position", side_effect=lambda: rl.Vector2(0.0, 0.0))
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(survival_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    mode.update(1.0 / 60.0)

    assert mode.player.health < 0.0
    assert mode._game_over_active is False
    for _ in range(120):
        mode.update(1.0 / 60.0)
        if mode._game_over_active:
            break
    assert mode._game_over_active is True
