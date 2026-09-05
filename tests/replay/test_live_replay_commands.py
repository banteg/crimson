from __future__ import annotations

import pytest

from crimson.dbg.state_digest import session_digest
from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand
from grim.geom import Vec2


@pytest.mark.parametrize("perk", [PerkId.REFLEX_BOOSTED, PerkId.BANDAGE, PerkId.INSTANT_WINNER, PerkId.AMMO_MANIAC])
@pytest.mark.parametrize("pick_count", [1, 2])
def test_live_perk_commands_match_recorded_prelude(perk: PerkId, pick_count: int) -> None:
    recorder = ReplayRecorder(ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF))
    commands = (PerkMenuOpenCommand(player_index=0),) + (
        PerkPickCommand(player_index=0, choice_index=0),
    ) * pick_count
    inputs = (PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 512.0)),)
    recorder.record_tick(inputs, commands=commands, dt=1 / 60)
    replay = recorder.finish()
    live = PlaybackDriver(replay)
    playback = PlaybackDriver(replay)
    for driver in (live, playback):
        selection = driver.world.state.perk_selection
        selection.pending_count = pick_count
        selection.choices_dirty = False
        selection.choices = [perk] * 7

    live_tick = live.session.step_tick(dt=1 / 60, inputs=inputs, commands=commands)
    replay_tick = playback.step_tick(0).payload

    assert live_tick == replay_tick
    assert live.world.players == playback.world.players
    assert live.world.state.rng.state == playback.world.state.rng.state
    assert live.world.state.perk_selection == playback.world.state.perk_selection
    assert live.session.elapsed_ms == playback.session.elapsed_ms
    assert session_digest(live.session) == session_digest(playback.session)
    if perk == PerkId.REFLEX_BOOSTED and pick_count == 1:
        assert live.session.elapsed_ms == 15.0
