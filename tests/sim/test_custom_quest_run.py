from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.custom import CustomQuest, variant_index
from crimson.quests.dsl import build_custom_quest
from crimson.quests.level import QuestLevel
from crimson.quests.types import QuestContext, QuestDefinition
from crimson.replay import dump_replay, load_replay
from crimson.replay.codec import ReplayCodecError
from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.sim.mode_updates import QuestSpawnState
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from grim.rand import CrtRand

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "replays"


def stock_as_custom(quest: QuestDefinition) -> CustomQuest:
    """A stock quest's own tables, for builders that draw nothing."""
    tables: list[tuple] = []
    variants = [0] * 8
    for player_count in (1, 2, 3, 4):
        for hardcore in (False, True):
            table = tuple(quest.builder(QuestContext(player_count=player_count, hardcore=hardcore, rng=CrtRand(0))))
            if table not in tables:
                tables.append(table)
            variants[variant_index(player_count=player_count, hardcore=hardcore)] = tables.index(table)
    return CustomQuest(
        title=quest.title,
        start_weapon_id=quest.start_weapon_id,
        terrain_slots=quest.terrain_slots,
        tables=tuple(tables),
        variants=tuple(variants),
    )


def crosswind() -> CustomQuest:
    return build_custom_quest(files("crimson.quests.dsl").joinpath("examples", "crosswind.quest").read_text())


# Builders that draw nothing, on levels without level-specific rules: their tables loaded as a
# custom quest leave the run exactly as the stock start does.
@pytest.mark.parametrize("name", ["quest-1.1-completed.crd", "quest-2.3-completed.crd"])
def test_a_stock_table_as_a_custom_quest_replays_the_stock_recording(name):
    replay = load_replay((FIXTURES / name).read_bytes())
    assert replay.run.quest_level is not None
    quest = quest_by_level(replay.run.quest_level)
    assert quest is not None
    run = msgspec.structs.replace(replay.run, quest_level=None, custom_quest=stock_as_custom(quest))
    custom = msgspec.structs.replace(replay, run=run)
    assert build_verify_playback_driver(custom, warn_on_version_mismatch=False).run() == replay.result


@pytest.mark.parametrize("hardcore", (False, True))
def test_a_custom_start_loads_its_table_without_stock_progress(hardcore):
    quest = crosswind()
    prepared = initialize_run(RunSpec(game_mode_id=GameMode.QUESTS, seed=7, hardcore=hardcore, custom_quest=quest))
    world = prepared.session.world
    spawn_state = prepared.session.mode_state
    assert isinstance(spawn_state, QuestSpawnState)
    assert spawn_state.spawn_entries == quest.entries(player_count=1, hardcore=hardcore)
    assert prepared.quest is None
    assert world.state.quest_level is None
    assert all(player.weapon.weapon_id == quest.start_weapon_id for player in world.players)
    assert prepared.terrain.terrain_slots == quest.terrain_slots
    assert (
        world.state.status.quest_play_counts
        == RunSpec(game_mode_id=GameMode.QUESTS, seed=7).status.as_status_data().quest_play_counts
    )


@pytest.mark.parametrize(
    "spec",
    [
        RunSpec(game_mode_id=GameMode.QUESTS, seed=1),
        RunSpec(game_mode_id=GameMode.QUESTS, seed=1, quest_level=QuestLevel(1, 1), custom_quest=crosswind()),
        RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, custom_quest=crosswind()),
    ],
)
def test_a_run_plays_exactly_one_quest(spec):
    with pytest.raises(ValueError, match="quest"):
        initialize_run(spec)


def test_custom_quest_replays_round_trip_and_reject_bad_definitions():
    replay = load_replay((FIXTURES / "quest-1.1-completed.crd").read_bytes())
    quest = crosswind()
    run = msgspec.structs.replace(replay.run, quest_level=None, custom_quest=quest)
    custom = msgspec.structs.replace(replay, run=run)
    assert load_replay(dump_replay(custom)).run == run
    untitled = msgspec.structs.replace(run, custom_quest=msgspec.structs.replace(quest, title=""))
    with pytest.raises(ReplayCodecError, match="run.custom_quest: title"):
        dump_replay(msgspec.structs.replace(replay, run=untitled))
    both = msgspec.structs.replace(run, quest_level=QuestLevel(1, 1))
    with pytest.raises(ReplayCodecError, match="exactly one"):
        dump_replay(msgspec.structs.replace(replay, run=both))
