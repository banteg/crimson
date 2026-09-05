from __future__ import annotations

from pathlib import Path

from crimson.modes.quest_mode import QuestMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.weapons import WEAPON_BY_ID
from grim.config import ensure_crimson_cfg
from grim.rand import Crand
from grim.view import ViewContext
from tests.support.audio import sfx_ids


def test_quest_failed_outcome_captures_all_player_health_values(tmp_path: Path, mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.gameplay.player_count = 4
    ctx = ViewContext(assets_dir=assets_dir)

    mocker.patch.object(QuestMode, "apply_terrain_setup", return_value=None)
    mode = QuestMode(ctx, config=cfg, audio_rng=Crand(0xBEEF))
    mode.start_run(QuestLevel(1, 1), status=None)
    health_values = (91.2, 50.6, 10.4, 0.49)
    for idx, health in enumerate(health_values):
        mode.sim_world.players[idx].health = float(health)
    mode._close_failed_run()
    outcome = mode.consume_outcome()
    assert outcome is not None
    assert outcome.player_health_values == health_values
    assert outcome.player_health == health_values[0]
    assert outcome.player2_health == health_values[1]


def test_start_run_queues_start_weapon_assign_sfx(tmp_path: Path, mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.gameplay.player_count = 2
    ctx = ViewContext(assets_dir=assets_dir)

    mocker.patch.object(QuestMode, "apply_terrain_setup", return_value=None)
    mode = QuestMode(ctx, config=cfg, audio_rng=Crand(0xBEEF))
    mode.start_run(QuestLevel(1, 1), status=None)

    quest = quest_by_level(QuestLevel(1, 1))
    assert quest is not None
    weapon = WEAPON_BY_ID[quest.start_weapon_id]
    reload_sfx = weapon.reload_sound
    assert sfx_ids(mode.state.sfx_queue) == [reload_sfx] * len(mode.sim_world.players)


def test_start_run_uses_session_rng_seed_instead_of_fixed_level_seed(tmp_path: Path, mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    ctx = ViewContext(assets_dir=assets_dir)

    mocker.patch.object(QuestMode, "apply_terrain_setup", return_value=None)
    mode = QuestMode(ctx, config=cfg, audio_rng=Crand(0xBEEF))

    seed_before_run = 0xCAFE
    mode.state.rng.srand(seed_before_run)

    reset_spy = mocker.spy(mode.world_runtime, "reset")
    mode.start_run(QuestLevel(1, 1), status=None)

    assert reset_spy.call_args is not None
    assert int(reset_spy.call_args.kwargs["seed"]) == int(seed_before_run)
    assert int(reset_spy.call_args.kwargs["seed"]) != 101
    assert mode._replay_recorder is not None
    assert int(mode._replay_recorder.header.seed) == int(seed_before_run)
