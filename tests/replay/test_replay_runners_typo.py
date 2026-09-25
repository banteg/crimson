from __future__ import annotations

from crimson.replay import Replay
from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.sim.bootstrap import advance_unlock_terrain
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import TypoCharCommand, TypoSubmitCommand
from crimson.sim.run_spec import WORLD_SIZE
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.replay_runner_helpers import _blank_typo_replay, _run_verify_playback, finish_replay


def _reload_submit_replay(
    *,
    seed: int = 0x1234,
    dictionary_words: tuple[str, ...] = (),
    highscore_names: tuple[str, ...] = (),
) -> Replay:
    rec = _blank_typo_replay(
        ticks=0,
        seed=seed,
        typo_dictionary_words=tuple(dictionary_words),
        typo_highscore_names=tuple(highscore_names),
    )
    baseline = PlayerInput(aim=Vec2(512.0, 512.0))
    for ch in "reload":
        rec.record_tick([baseline], commands=[TypoCharCommand(player_index=0, ch=ch)])
    rec.record_tick([baseline], commands=[TypoSubmitCommand(player_index=0)])
    return finish_replay(rec)


def test_typo_runner_is_deterministic_and_uses_submit_counts_for_run_result() -> None:
    replay = _reload_submit_replay(seed=0x1234)

    result0 = _run_verify_playback(replay)
    result1 = _run_verify_playback(replay)

    assert result0 == result1 == replay.result
    assert result0.elapsed_ms == 7 * int(1000.0 / 60.0)
    assert result0.players[0].shots_fired == 1
    assert result0.players[0].shots_hit == 0


def test_typo_runner_uses_header_seed_for_startup_terrain_prelude() -> None:
    rec = _blank_typo_replay(ticks=0, seed=0x1234)
    replay = finish_replay(rec)
    driver = build_verify_playback_driver(replay)

    rng = Crand(int(replay.run.seed))
    terrain = advance_unlock_terrain(
        rng,
        unlock_index=int(replay.run.status.quest_unlock_index),
        width=int(WORLD_SIZE),
        height=int(WORLD_SIZE),
    )

    terrain_setup = driver.terrain_setup
    assert terrain_setup is not None
    assert terrain_setup.terrain_slots == terrain.terrain_slots
    assert terrain_setup.terrain_seed == int(terrain.terrain_seed)
    assert int(driver.world.state.rng.state) == int(rng.state)


def test_typo_runner_uses_header_dictionary_words() -> None:
    replay = _reload_submit_replay(
        seed=0x1234,
        dictionary_words=("amber", "onyx"),
    )

    driver = build_verify_playback_driver(replay)

    assert driver.world.state.typo.dictionary_words == ("amber", "onyx")


def test_typo_runner_uses_header_highscore_names() -> None:
    replay = _reload_submit_replay(
        seed=0x1234,
        highscore_names=("quick", "brown", "fox"),
    )

    driver = build_verify_playback_driver(replay)

    assert driver.world.state.typo.highscore_names == ("quick", "brown", "fox")


def test_typo_runner_checkpoints_capture_typo_state() -> None:
    replay = _reload_submit_replay(seed=0x1234)
    checkpoints = []

    _run_verify_playback(
        replay,
        checkpoints_out=checkpoints,
        checkpoint_ticks={6},
    )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [6]
    assert checkpoints[0].typo is not None
    assert checkpoints[0].typo.input_text == ""
    assert checkpoints[0].typo.submit_count == 1
    assert checkpoints[0].typo.match_count == 0


def test_typo_runner_ignores_input_fire_flags() -> None:
    baseline = finish_replay(_blank_typo_replay(ticks=120, seed=0x1234))
    firing = _blank_typo_replay(ticks=0, seed=0x1234)
    for _ in range(120):
        firing.record_tick([PlayerInput(aim=Vec2(800.0, 512.0), fire_down=True, fire_pressed=True, reload_pressed=True)])

    result = finish_replay(firing).result

    assert result.players[0].shots_fired == 0
    assert result.kills == baseline.result.kills
    assert result.players[0].experience == baseline.result.players[0].experience
