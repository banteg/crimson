from __future__ import annotations

from importlib.resources import files

import msgspec
import pytest

from crimson.bonuses.ids import BonusId
from crimson.creatures.spawn_ids import SpawnId
from crimson.perks.ids import PerkId
from crimson.quests.custom import DROPPABLE_WEAPONS, CustomQuest, validate_custom_quest
from crimson.quests.dsl import QuestCompileError, build_custom_quest, compile_quest
from crimson.quests.dsl.stock import stock_source
from crimson.weapons import WeaponId
from grim.geom import Vec2


def example(name: str) -> str:
    return files("crimson.quests.dsl").joinpath("examples", f"{name}.quest").read_text(encoding="utf-8")


def test_custom_quest_plays_what_the_compiler_constructs():
    source = stock_source("4.7")
    quest = build_custom_quest(source, seed=7)
    plan = compile_quest(source, seed=7, player_count=1, hardcore=False)
    assert quest.entries == plan.entries


def test_the_digest_covers_gameplay_and_restrictions_not_the_title_or_author():
    quest = build_custom_quest(example("crosswind"))
    renamed = msgspec.structs.replace(quest, title="Another name", author="someone")
    rearmed = msgspec.structs.replace(quest, start_weapon_id=WeaponId.PISTOL)
    restricted = msgspec.structs.replace(quest, no_bonuses=(BonusId.NUKE,))
    assert renamed.digest() == quest.digest()
    assert rearmed.digest() != quest.digest()
    assert restricted.digest() != quest.digest()


def replace_first_entry(quest: CustomQuest, **changes) -> CustomQuest:
    return msgspec.structs.replace(
        quest,
        entries=(msgspec.structs.replace(quest.entries[0], **changes), *quest.entries[1:]),
    )

@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda q: msgspec.structs.replace(q, title=""), "title"),
        (lambda q: msgspec.structs.replace(q, title="café"), "title"),
        (lambda q: msgspec.structs.replace(q, author=""), "author"),
        (lambda q: msgspec.structs.replace(q, author="x" * 32), "author"),
        (lambda q: msgspec.structs.replace(q, start_weapon_id=WeaponId.NONE), "starting weapon"),
        (lambda q: msgspec.structs.replace(q, terrain_slots=(0, 8, 0)), "terrain"),
        (lambda q: msgspec.structs.replace(q, entries=()), "1..256 entries"),
        (lambda q: msgspec.structs.replace(q, entries=q.entries * 3), "1..256 entries"),
        (lambda q: msgspec.structs.replace(q, no_bonuses=(BonusId.POINTS,)), "no_bonuses"),
        (lambda q: msgspec.structs.replace(q, no_bonuses=(BonusId.FREEZE, BonusId.NUKE)), "no_bonuses"),
        (lambda q: msgspec.structs.replace(q, no_perks=(PerkId.ANTIPERK,)), "no_perks"),
        (lambda q: msgspec.structs.replace(q, no_weapons=(WeaponId.PISTOL,)), "no_weapons"),
        (lambda q: replace_first_entry(q, spawn_id=SpawnId.UNUSED_02), "unused"),
        (lambda q: replace_first_entry(q, trigger_ms=-1), "trigger"),
        (lambda q: replace_first_entry(q, pos=Vec2(0.1, 0.0)), "float32"),
        (lambda q: replace_first_entry(q, pos=Vec2(1e300, 0.0)), "positions must be in"),
        (lambda q: replace_first_entry(q, heading=1e300), "float32"),
        (lambda q: replace_first_entry(q, pos=Vec2(1e20, 512.0)), "positions must be in"),
        (lambda q: replace_first_entry(q, pos=Vec2(512.0, -1025.0)), "positions must be in"),
        (lambda q: replace_first_entry(q, heading=float("nan")), "float32"),
        (lambda q: replace_first_entry(q, count=0), "copies"),
        (lambda q: replace_first_entry(q, count=385), "copies"),
    ],
)
def test_invalid_definitions_are_rejected(edit, message):
    quest = build_custom_quest(example("crosswind"))
    with pytest.raises(ValueError, match=message):
        validate_custom_quest(edit(quest))


def test_the_recipe_names_its_author_for_the_byline():
    source = example("crosswind").replace(
        'quest "Crosswind" version 1\n',
        'quest "Crosswind" version 1\nauthor "banteg"\n',
    )
    quest = build_custom_quest(source)
    assert (quest.author, quest.byline) == ("banteg", "by banteg")
    assert compile_quest(source).author == "banteg"
    assert build_custom_quest(example("crosswind")).byline == ""


@pytest.mark.parametrize(
    ("setting", "message"),
    [('author ""', "author"), ('author "a"\nauthor "b"', "duplicate author")],
)
def test_bad_author_settings_are_rejected(setting, message):
    with pytest.raises(QuestCompileError, match=message):
        compile_quest(f'quest "Bylined" version 1\n{setting}\nat 1s:\n    spawn alien.small_gray at center')


def test_dsl_restrictions_and_fixed_weapon_expand_cleanly():
    quest = build_custom_quest(
        """quest "Restricted" version 1
weapon shotgun
no_bonuses [nuke, freeze]
no_perks [poison_bullets, bloody_mess]
no_weapons [ion_cannon]
at 1s:
    spawn alien.fast at corners() copies 2
""",
    )
    assert quest.no_bonuses == (BonusId.NUKE, BonusId.FREEZE)
    assert quest.no_perks == (PerkId.BLOODY_MESS_QUICK_LEARNER, PerkId.POISON_BULLETS)
    assert quest.no_weapons == (WeaponId.ION_CANNON,)
    assert len(quest.entries) == 4
    assert all(entry.count == 2 for entry in quest.entries)

    fixed = build_custom_quest(example("same-problem-shotgun"))
    assert fixed.no_bonuses == (BonusId.WEAPON,)
    assert fixed.no_perks == (PerkId.ALTERNATE_WEAPON, PerkId.RANDOM_WEAPON)
    assert fixed.no_weapons == DROPPABLE_WEAPONS


def test_tuple_points_and_expanded_aliases_work_across_helpers():
    quest = build_custom_quest(
        """quest "Tuples and Aliases" version 1
at 1s:
    spawn lizard.flanker at ring((512, 512), 120, 4) copies 2 heading facing((256, 512), (512, 512))
    spawn nest.alien_weak at rotate([(256, 256), (768, 256)], 90deg, around=(512, 512))
""",
    )
    assert len(quest.entries) == 6
    assert [entry.spawn_id for entry in quest.entries] == [
        SpawnId.AI1_LIZARD_BLUE_TINT_1C,
        SpawnId.AI1_LIZARD_BLUE_TINT_1C,
        SpawnId.AI1_LIZARD_BLUE_TINT_1C,
        SpawnId.AI1_LIZARD_BLUE_TINT_1C,
        SpawnId.DEN_ALIEN_WEAK_SMALL_09,
        SpawnId.DEN_ALIEN_WEAK_SMALL_09,
    ]
