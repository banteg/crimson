from __future__ import annotations

from pathlib import Path

import msgspec

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.replay import Replay, ReplayRecorder
from crimson.replay.checkpoints import ReplayCheckpoint, build_checkpoint
from crimson.replay.driver.playback_driver import build_runtime_playback_driver, build_verify_playback_driver
from crimson.replay.input_codec import pack_tick
from crimson.sim.input import PlayerInput
from crimson.sim.run_spec import RunSpec
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.replay_runner_helpers import _run_verify_playback, unverified_replay
from tests.support.world_runtime import WorldRuntimeHost


def _checkpoint_state_projection(checkpoint: ReplayCheckpoint) -> dict[str, object]:
    obj = msgspec.to_builtins(checkpoint)
    for key in ("elapsed_ms", "rng_state", "deaths", "perk", "events"):
        obj.pop(key, None)
    return obj


def _build_replay(*, mode: int, ticks: int, seed: int = 0x1234) -> Replay:
    game_mode = GameMode(int(mode))
    rec = ReplayRecorder(
        RunSpec(
            game_mode_id=game_mode,
            seed=int(seed),
            quest_level=(QuestLevel(1, 1) if game_mode == GameMode.QUESTS else None),
        ),
    )
    for idx in range(int(ticks)):
        rec.record(pack_tick([
                PlayerInput(
                    aim=Vec2(512.0 + float(idx), 512.0),
                    fire_down=bool(idx % 2 == 0),
                    fire_pressed=bool(idx % 3 == 0),
                    reload_pressed=bool(idx == int(ticks) - 1),
                ),
            ]))
    return unverified_replay(rec)


def _live_runtime_checkpoints(
    replay: Replay,
    *,
    spawn_entries: tuple | None = None,
    start_weapon_id=None,
) -> list[ReplayCheckpoint]:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    driver = build_runtime_playback_driver(
        replay,
        max_ticks=None,
        trace_rng=False,
        spawn_entries=spawn_entries,
        start_weapon_id=start_weapon_id,
    )
    runtime.start_session(driver.session)

    checkpoints: list[ReplayCheckpoint] = []
    for tick_index in range(len(replay.ticks)):
        tick = driver.step_tick(tick_index)
        step = tick.payload
        runtime.advance_presentation_clock(dt_sim=step.dt_sim)
        runtime.render_resources.consume_terrain_fx_batch(step.presentation.terrain_fx)

        checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=runtime.world,
                elapsed_ms=float(driver.elapsed_ms),
                deaths=step.events.deaths,
                events=step.events,
            ),
        )

    return checkpoints


def _quest_spawn_entries(*, level: str, player_count: int, seed: int) -> tuple:
    quest = quest_by_level(QuestLevel.parse(level))
    assert quest is not None
    return build_quest_spawn_table(quest, QuestContext(player_count=int(player_count), rng=Crand(int(seed))))


def _live_quest_checkpoints(replay: Replay, *, spawn_entries: tuple) -> list[ReplayCheckpoint]:
    return _live_runtime_checkpoints(replay, spawn_entries=spawn_entries)


def test_survival_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.SURVIVAL), ticks=6, seed=0x1234)

    live = _live_runtime_checkpoints(replay)
    headless: list[ReplayCheckpoint] = []
    _run_verify_playback(
        replay,
        checkpoints_out=headless,
        checkpoint_ticks=set(range(len(replay.ticks))),
    )

    assert [_checkpoint_state_projection(ck) for ck in live] == [_checkpoint_state_projection(ck) for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]


def test_rush_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.RUSH), ticks=6, seed=0x5678)

    live = _live_runtime_checkpoints(replay)
    headless: list[ReplayCheckpoint] = []
    _run_verify_playback(
        replay,
        checkpoints_out=headless,
        checkpoint_ticks=set(range(len(replay.ticks))),
    )

    assert [_checkpoint_state_projection(ck) for ck in live] == [_checkpoint_state_projection(ck) for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]


def test_runtime_playback_driver_matches_verify_terrain_fx_output() -> None:
    replay = _build_replay(mode=int(GameMode.SURVIVAL), ticks=1, seed=0x1234)
    runtime_driver = build_runtime_playback_driver(
        replay,
        max_ticks=None,
        trace_rng=False,
    )
    verify_driver = build_verify_playback_driver(replay)

    runtime_tick = runtime_driver.step_tick(0)
    verify_tick = verify_driver.step_tick(0)

    assert runtime_tick.payload.presentation.terrain_fx == verify_tick.payload.presentation.terrain_fx


def test_quest_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.QUESTS), ticks=6, seed=101)
    spawn_entries = _quest_spawn_entries(
        level="1.1",
        player_count=int(replay.run.player_count),
        seed=int(replay.run.seed),
    )

    live = _live_quest_checkpoints(replay, spawn_entries=spawn_entries)
    headless: list[ReplayCheckpoint] = []
    _run_verify_playback(
        replay,
        spawn_entries=spawn_entries,
        checkpoints_out=headless,
        checkpoint_ticks=set(range(len(replay.ticks))),
    )

    assert [_checkpoint_state_projection(ck) for ck in live] == [_checkpoint_state_projection(ck) for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]
