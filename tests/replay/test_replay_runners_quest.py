from __future__ import annotations

import msgspec

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.replay.driver.playback_driver import PlaybackWalkObserver, build_verify_playback_driver
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.bootstrap import advance_explicit_terrain, advance_unlock_terrain
from crimson.sim.hooks import TickResult
from crimson.sim.input_providers import GameFrameRngAdvanceOperation, PerkPickCommand
from crimson.sim.world_state import WorldState
from crimson.weapons import WEAPON_BY_ID
from grim.rand import Crand
from tests.support.replay_runner_helpers import (
    _blank_quest_replay,
    _collect_verify_replay_info,
    _quest_spawn_entries,
    _run_verify_playback,
)


class _ExperienceWalkObserver(PlaybackWalkObserver):
    observed_before: list[int]
    observed_after: list[int]

    def before_tick(self, tick_index: int, world: WorldState, dt_tick: float) -> None:
        _ = tick_index, dt_tick
        self.observed_before.append(int(world.players[0].experience))

    def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
        _ = tick_result
        self.observed_after.append(int(world.players[0].experience))


def test_quest_runner_is_deterministic() -> None:
    _header, rec = _blank_quest_replay(ticks=10, seed=101)
    replay = rec.finish()
    spawn_entries = tuple(
        _quest_spawn_entries("1.1", player_count=int(replay.header.player_count), seed=int(replay.header.seed)),
    )

    result0 = _run_verify_playback(replay, spawn_entries=spawn_entries)
    result1 = _run_verify_playback(replay, spawn_entries=spawn_entries)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.QUESTS)
    assert result0.ticks == 10
    assert result0.elapsed_ms >= 0


def test_quest_runner_uses_replay_dt_rows_for_elapsed_ms() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], dt=0.5)
    spawn_entries = tuple(
        _quest_spawn_entries("1.1", player_count=int(replay.header.player_count), seed=int(replay.header.seed)),
    )

    result = _run_verify_playback(
        replay,
        spawn_entries=spawn_entries,
    )

    assert result.elapsed_ms == 500


def test_quest_runner_game_frame_rng_advance_prelude_shifts_rng_state() -> None:
    _header, rec = _blank_quest_replay(ticks=3, seed=101)
    replay = rec.finish()

    baseline = _run_verify_playback(replay, spawn_entries=())
    shifted_replay = msgspec.structs.replace(
        replay,
        ticks=[
            msgspec.structs.replace(tick, prelude=[GameFrameRngAdvanceOperation(frames=1)]) for tick in replay.ticks
        ],
    )
    shifted = _run_verify_playback(shifted_replay, spawn_entries=())
    shifted_again = _run_verify_playback(shifted_replay, spawn_entries=())

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_quest_runner_burns_spawn_builder_rng_even_with_injected_spawn_entries() -> None:
    _header, rec = _blank_quest_replay(ticks=0, seed=101)
    replay = msgspec.structs.replace(
        rec.finish(),
        header=msgspec.structs.replace(rec.header, quest_level=QuestLevel(1, 3)),
    )
    quest = quest_by_level(QuestLevel(1, 3))
    assert quest is not None

    ctx = QuestContext(
        width=int(replay.header.world_size),
        height=int(replay.header.world_size),
        player_count=int(replay.header.player_count),
    )
    rng = Crand(int(replay.header.seed))
    advance_unlock_terrain(
        rng,
        unlock_index=int(replay.header.status.quest_unlock_index),
        width=int(replay.header.world_size),
        height=int(replay.header.world_size),
    )
    # Native `quest_start_selected()` burns one `crt_rand()` before quest terrain.
    rng.rand_tagged(RngCallerStatic.QUEST_START_SELECTED_HIGHSCORE_RANDOM_TAG)
    quest_terrain = advance_explicit_terrain(
        rng,
        terrain_slots=quest.terrain_slots,
        width=int(replay.header.world_size),
        height=int(replay.header.world_size),
    )
    spawn_entries = tuple(
        build_quest_spawn_table(
            quest,
            ctx,
            rng=rng,
            hardcore=bool(replay.header.hardcore),
            full_version=True,
        ),
    )
    expected_rng_state = int(rng.state)

    baseline_driver = build_verify_playback_driver(replay)
    injected_driver = build_verify_playback_driver(replay, spawn_entries=spawn_entries)

    terrain_setup = baseline_driver.terrain_setup
    assert terrain_setup is not None
    assert terrain_setup.terrain_slots == quest.terrain_slots
    assert terrain_setup.terrain_seed == int(quest_terrain.terrain_seed)
    assert int(baseline_driver.world.state.rng.state) == expected_rng_state
    assert int(injected_driver.world.state.rng.state) == expected_rng_state


def test_quest_runner_replays_start_weapon_reload_sfx_at_tick_zero() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    checkpoints = []

    _run_verify_playback(
        replay,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0},
    )

    assert len(checkpoints) == 1
    tick0 = checkpoints[0]
    assert int(tick0.events.sfx_count) == 1

    quest = quest_by_level(QuestLevel(1, 1))
    assert quest is not None
    weapon = WEAPON_BY_ID[quest.start_weapon_id]
    expected_reload_sfx = weapon.reload_sound
    assert tick0.events.sfx_head == [expected_reload_sfx.value]


def test_quest_runner_ignores_stale_perk_pick_command() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        prelude=[PerkPickCommand(player_index=0, choice_index=0)],
    )

    result = _run_verify_playback(replay, spawn_entries=())
    assert result.ticks == 1


def test_quest_replay_info_elapsed_matches_run_replay() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], dt=0.5)

    run_result = _run_verify_playback(replay)
    info = _collect_verify_replay_info(replay)

    assert int(info.elapsed_ms) == int(run_result.elapsed_ms)


def test_playback_driver_tick_begin_observer_runs_before_step(mocker) -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    driver = build_verify_playback_driver(replay)
    observed_before: list[int] = []
    observed_after: list[int] = []

    real_step_tick = driver.step_tick

    def _step_tick_with_mutation(tick_index: int):
        driver.world.players[0].experience = 99
        return real_step_tick(tick_index)

    mocker.patch.object(driver, "step_tick", side_effect=_step_tick_with_mutation)

    driver.run(
        observer=_ExperienceWalkObserver(
            observed_before=observed_before,
            observed_after=observed_after,
        ),
    )

    assert observed_before == [0]
    assert observed_after == [99]
