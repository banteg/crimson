from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import msgspec
import pytest

from crimson.bonuses.ids import BonusId
from crimson.game_modes import GameMode
from crimson.perks.ids import PerkId
from crimson.quests import quest_by_level
from crimson.quests.custom import CustomQuest
from crimson.quests.dsl import build_custom_quest
from crimson.quests.level import QuestLevel
from crimson.quests.types import QuestContext, QuestDefinition
from crimson.replay import REPLAY_FORMAT_VERSION, dump_replay, load_replay
from crimson.replay.codec import ReplayCodecError, decode_replay_payload
from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.sim.mode_updates import QuestSpawnState
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from crimson.weapons import WeaponId
from grim.rand import CrtRand

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "replays"


def stock_as_custom(quest: QuestDefinition) -> CustomQuest:
    """A stock quest's 1-player normal table, for builders that draw nothing."""
    return CustomQuest(
        title=quest.title,
        start_weapon_id=quest.start_weapon_id,
        terrain_slots=quest.terrain_slots,
        entries=tuple(quest.builder(QuestContext(player_count=1, hardcore=False, rng=CrtRand(0)))),
    )

def crosswind() -> CustomQuest:
    return build_custom_quest(files("crimson.quests.dsl").joinpath("examples", "crosswind.quest").read_text())


# A builder that draws nothing, on a normal level without level-specific rules: its table loaded as a
# custom quest leaves the run exactly as the stock start does.
def test_a_stock_table_as_a_custom_quest_replays_the_stock_recording():
    replay = load_replay((FIXTURES / "quest-1.1-completed.crd").read_bytes())
    assert replay.run.quest_level is not None
    quest = quest_by_level(replay.run.quest_level)
    assert quest is not None
    run = msgspec.structs.replace(replay.run, quest_level=None, custom_quest=stock_as_custom(quest))
    custom = msgspec.structs.replace(replay, run=run)
    assert build_verify_playback_driver(custom, warn_on_version_mismatch=False).run() == replay.result


def test_a_custom_start_loads_its_table_and_restrictions_without_stock_progress():
    quest = msgspec.structs.replace(
        crosswind(),
        no_bonuses=(BonusId.NUKE, BonusId.WEAPON),
        no_perks=(PerkId.RANDOM_WEAPON,),
        no_weapons=(WeaponId.ION_CANNON,),
    )
    prepared = initialize_run(RunSpec(game_mode_id=GameMode.QUESTS, seed=7, custom_quest=quest))
    world = prepared.session.world
    spawn_state = prepared.session.mode_state
    assert isinstance(spawn_state, QuestSpawnState)
    assert spawn_state.spawn_entries == quest.entries
    assert prepared.quest is None
    assert world.state.quest_level is None
    assert all(player.weapon.weapon_id == quest.start_weapon_id for player in world.players)
    assert prepared.terrain.terrain_slots == quest.terrain_slots
    assert not world.state.bonus_available[int(BonusId.NUKE)]
    assert not world.state.bonus_available[int(BonusId.WEAPON)]
    assert world.state.bonus_available[int(BonusId.POINTS)]
    assert not world.state.perk_available[int(PerkId.RANDOM_WEAPON)]
    assert not world.state.weapon_available[int(WeaponId.ION_CANNON)]
    assert (
        world.state.status.quest_play_counts
        == RunSpec(game_mode_id=GameMode.QUESTS, seed=7).status.as_status_data().quest_play_counts
    )

@pytest.mark.parametrize(
    "spec",
    [
        RunSpec(game_mode_id=GameMode.QUESTS, seed=1),
        RunSpec(game_mode_id=GameMode.QUESTS, seed=1, quest_level=QuestLevel(1, 1), custom_quest=crosswind()),
        RunSpec(game_mode_id=GameMode.QUESTS, seed=1, hardcore=True, custom_quest=crosswind()),
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


def test_legacy_v33_custom_quest_replays_upgrade_on_decode():
    from crimson.replay.codec import _CustomQuestV33Legacy, _ReplayV33Legacy, _RunSpecV33Legacy

    replay = load_replay((FIXTURES / "quest-1.1-completed.crd").read_bytes())
    quest = crosswind()
    legacy_cq = _CustomQuestV33Legacy(
        title=quest.title,
        author=quest.author,
        start_weapon_id=int(quest.start_weapon_id),
        terrain_slots=quest.terrain_slots,
        tables=(quest.entries,),
        variants=(0,) * 8,
    )
    run_dict = msgspec.structs.asdict(replay.run)
    run_dict["quest_level"] = None
    run_dict["custom_quest"] = legacy_cq
    legacy_replay = _ReplayV33Legacy(
        format_version=33,
        game_version=replay.game_version,
        rules=replay.rules,
        recorder=replay.recorder,
        pilot=replay.pilot,
        run=_RunSpecV33Legacy(**run_dict),
        result=replay.result,
        ticks=replay.ticks,
    )
    payload = msgspec.msgpack.encode(legacy_replay)
    decoded = decode_replay_payload(payload)
    assert decoded.run.custom_quest == quest
    bad_weapon = msgspec.structs.replace(legacy_cq, start_weapon_id=999)
    bad_run = msgspec.structs.replace(legacy_replay.run, custom_quest=bad_weapon)
    with pytest.raises(ReplayCodecError, match="start_weapon_id"):
        decode_replay_payload(msgspec.msgpack.encode(msgspec.structs.replace(legacy_replay, run=bad_run)))

def test_a_survival_replay_carrying_both_quests_is_refused():
    replay = load_replay((FIXTURES / "survival-135302.crd").read_bytes())
    run = msgspec.structs.replace(replay.run, quest_level=QuestLevel(1, 1), custom_quest=crosswind())
    with pytest.raises(ReplayCodecError, match="other modes need neither"):
        dump_replay(msgspec.structs.replace(replay, run=run))


def test_an_overflowing_custom_quest_position_is_a_codec_error():
    replay = load_replay((FIXTURES / "quest-1.1-completed.crd").read_bytes())
    quest = crosswind()
    far = msgspec.structs.replace(quest.entries[0], pos=msgspec.structs.replace(quest.entries[0].pos, x=1e300))
    quest = msgspec.structs.replace(quest, entries=(far, *quest.entries[1:]))
    run = msgspec.structs.replace(replay.run, quest_level=None, custom_quest=quest)
    payload = msgspec.msgpack.encode(msgspec.structs.replace(replay, format_version=REPLAY_FORMAT_VERSION, run=run))
    with pytest.raises(ReplayCodecError, match="run.custom_quest: positions"):
        decode_replay_payload(payload)
