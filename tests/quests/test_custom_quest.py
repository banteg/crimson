from __future__ import annotations

from importlib.resources import files

import msgspec
import pytest

from crimson.creatures.spawn_ids import SpawnId
from crimson.quests.custom import CustomQuest, validate_custom_quest
from crimson.quests.dsl import build_custom_quest, compile_quest
from crimson.quests.dsl.stock import stock_source
from crimson.weapons import WeaponId
from grim.geom import Vec2


def example(name: str) -> str:
    return files("crimson.quests.dsl").joinpath("examples", f"{name}.quest").read_text(encoding="utf-8")


def test_every_variant_plays_what_the_compiler_constructs():
    source = stock_source("4.7")
    quest = build_custom_quest(source, seed=7)
    for player_count in (1, 2, 3, 4):
        for hardcore in (False, True):
            plan = compile_quest(source, seed=7, player_count=player_count, hardcore=hardcore)
            assert quest.entries(player_count=player_count, hardcore=hardcore) == plan.entries


def test_variants_share_tables_a_recipe_does_not_vary():
    quest = build_custom_quest(example("crosswind"))
    assert len(quest.tables) == 1
    assert quest.variants == (0,) * 8


def test_the_digest_covers_gameplay_not_the_title():
    quest = build_custom_quest(example("crosswind"))
    renamed = msgspec.structs.replace(quest, title="Another name")
    rearmed = msgspec.structs.replace(quest, start_weapon_id=WeaponId.PISTOL)
    assert renamed.digest() == quest.digest()
    assert rearmed.digest() != quest.digest()


def replace_first_entry(quest: CustomQuest, **changes) -> CustomQuest:
    table = quest.tables[0]
    return msgspec.structs.replace(quest, tables=((msgspec.structs.replace(table[0], **changes), *table[1:]),))


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda q: msgspec.structs.replace(q, title=""), "title"),
        (lambda q: msgspec.structs.replace(q, title="café"), "title"),
        (lambda q: msgspec.structs.replace(q, start_weapon_id=WeaponId.NONE), "starting weapon"),
        (lambda q: msgspec.structs.replace(q, terrain_slots=(0, 8, 0)), "terrain"),
        (lambda q: msgspec.structs.replace(q, variants=(0,) * 7), "variants"),
        (lambda q: msgspec.structs.replace(q, variants=(1,) * 8), "variants"),
        (lambda q: msgspec.structs.replace(q, tables=(q.tables[0], q.tables[0])), "variants"),
        (lambda q: msgspec.structs.replace(q, tables=((),)), "1..256 entries"),
        (lambda q: msgspec.structs.replace(q, tables=(q.tables[0] * 3,)), "1..256 entries"),
        (lambda q: replace_first_entry(q, spawn_id=SpawnId.UNUSED_02), "unused"),
        (lambda q: replace_first_entry(q, trigger_ms=-1), "trigger"),
        (lambda q: replace_first_entry(q, pos=Vec2(0.1, 0.0)), "float32"),
        (lambda q: replace_first_entry(q, pos=Vec2(1e300, 0.0)), "positions must be in"),
        (lambda q: replace_first_entry(q, heading=1e300), "float32"),
        (lambda q: replace_first_entry(q, pos=Vec2(1e20, 512.0)), "positions must be in"),
        (lambda q: replace_first_entry(q, pos=Vec2(512.0, -1025.0)), "positions must be in"),
        (lambda q: replace_first_entry(q, heading=float("nan")), "float32"),
        (lambda q: replace_first_entry(q, count=0), "copies"),
        (lambda q: replace_first_entry(q, count=380), "hardcore|per-trigger"),
    ],
)
def test_invalid_definitions_are_rejected(edit, message):
    quest = build_custom_quest(example("crosswind"))
    with pytest.raises(ValueError, match=message):
        validate_custom_quest(edit(quest))
