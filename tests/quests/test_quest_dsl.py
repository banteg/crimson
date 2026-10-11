from __future__ import annotations

import math
import struct
from dataclasses import replace
from importlib.resources import files

import pytest

from crimson.creatures.spawn_ids import SpawnId
from crimson.quests.database import QUESTS
from crimson.quests.dsl import CompileLimits, QuestCompileError, compile_quest
from crimson.quests.dsl.stock import stock_source
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from grim.rand import CrtRand, RecordingCrand


@pytest.mark.parametrize("quest", QUESTS, ids=lambda quest: quest.level.text)
@pytest.mark.parametrize("players", (1, 2, 3, 4))
@pytest.mark.parametrize("hardcore", (False, True))
@pytest.mark.parametrize("seed", (0, 1, 0xBEEF, 0xFFFFFFFF))
def test_all_stock_recipes_match_entries_and_rng_trace(quest, players, hardcore, seed):
    native_rng = RecordingCrand(CrtRand(seed))
    recipe_rng = RecordingCrand(CrtRand(seed))
    expected = build_quest_spawn_table(quest, QuestContext(player_count=players, hardcore=hardcore, rng=native_rng))
    plan = compile_quest(
        stock_source(quest.level.text),
        context=QuestContext(player_count=players, hardcore=hardcore, rng=recipe_rng),
    )
    assert plan.entries == expected
    assert [struct.pack("<fff", entry.pos.x, entry.pos.y, entry.heading) for entry in plan.entries] == [
        struct.pack("<fff", entry.pos.x, entry.pos.y, entry.heading) for entry in expected
    ]
    assert recipe_rng.records == native_rng.records
    assert plan.construction_rng_state == native_rng.state
    assert plan.start_weapon_id == quest.start_weapon_id
    assert plan.terrain_slots == quest.terrain_slots


def test_pattern_placement_sorting_and_source_mapping():
    plan = compile_quest("""quest "Circuit" version 1
pattern socket(pos):
    spawn nest.alien_slow at pos
let sockets = ring(center, radius=320, count=8)
repeat 8 as i:
    at 1s + i * 6s:
        socket(sockets[i])
at 500ms:
    place alien.small_gray on line(point(100, 100), point(10, 0), 3)
""")
    assert len(plan.entries) == 11
    assert [entry.trigger_ms for entry in plan.entries] == [
        500,
        500,
        500,
        1000,
        7000,
        13000,
        19000,
        25000,
        31000,
        37000,
        43000,
    ]
    assert [entry.pos.x for entry in plan.entries[:3]] == [100, 110, 120]
    assert plan.locations[0].line == 9
    assert plan.locations[-1].line == 3
    assert plan.locations[-1].iterations == (7,)


def test_seeded_construction_is_repeatable_without_a_gameplay_context():
    source = """quest "Draws" version 1
repeat 20 as i:
    at i * 1s:
        spawn choose([spider.boss, spider.splitter]) at point(rand_int(100, 900), 512)
"""
    assert compile_quest(source, seed=42) == compile_quest(source, seed=42)
    assert compile_quest(source, seed=42).entries != compile_quest(source, seed=43).entries


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("while true:\n    rand()", "work budget"),
        ("let xs = range(1000000000)", "collection limit"),
        ("let xs = [1]\nvar ys = xs\nys *= 1000000000", "arithmetic requires numbers"),
        ("at 1s:\n    place alien.small_gray on line(center, point(1, 0), 257)", "entry limit"),
        ("at -1ms:\n    spawn alien.small_gray at center", "authored horizon"),
        ("at 1s:\n    burst alien.small_gray at center copies 0", "copies must be positive"),
        ("at 1s:\n    spawn 999 at center", "not a valid SpawnId"),
        ("at 1s:\n    spawn alien.small_gray at point(1e309, 0)", "finite"),
        ("let fixed = 1\nfixed = 2", "immutable"),
        ("spawn alien.small_gray at center", "inside an at"),
        ("import os", "unsupported syntax"),
        ("let xs = [i for i in range(10)]", "unsupported syntax"),
        ("let value = center.__class__", "reserved"),
        ("pattern loop():\n    loop()\nloop()", "cannot recurse"),
        ("var a = [0]\nrepeat 60 as i:\n    a = [a, a]\nlet b = a == a", "scalar"),
        ("var a = [0]\nrepeat 60 as i:\n    a = [a, a]\nlet b = min(a)", "require numbers"),
    ],
)
def test_invalid_or_excessive_construction_is_rejected(body, message):
    with pytest.raises(QuestCompileError, match=message):
        compile_quest('quest "Invalid" version 1\n' + body, limits=replace(CompileLimits(), work=5000))


def test_errors_identify_the_original_source_line():
    with pytest.raises(QuestCompileError) as error:
        compile_quest('quest "Bad" version 1\nat 2s:\n    spawn spider.boss at missing')
    assert error.value.line == 3


def test_unit_tokens_leave_strings_and_comments_unchanged():
    plan = compile_quest("""quest "30s false" version 1
let side = "west"
at 2.5s: # 5s
    spawn spider.boss at edge(side) heading 90deg
""")
    assert plan.title == "30s false"
    assert plan.entries[0].trigger_ms == 2500
    assert plan.entries[0].pos.x == -64


@pytest.mark.parametrize(
    "source",
    [
        'quest "Bad" version 2',
        'quest "Bad" version 1\nterrain (0, 8, 0)',
        'quest "Bad" version 1\nweapon none',
        'quest "Bad" version 1\norder arbitrary',
        'quest "Bad" version 1\nweapon pistol\nweapon shotgun',
    ],
)
def test_invalid_settings_are_rejected(source):
    with pytest.raises(QuestCompileError):
        compile_quest(source)


def example_source(name: str) -> str:
    return files("crimson.quests.dsl").joinpath("examples", f"{name}.quest").read_text(encoding="utf-8")


@pytest.mark.parametrize("seed", (0, 1, 0xBEEF))
@pytest.mark.parametrize(
    ("name", "entries"),
    [
        ("clockwork", 17),
        ("crosswind", 120),
        ("spiral-descent", 60),
        ("accelerating-encounters", 12),
        ("shuffled-threats", 8),
        ("plasma-orchard", 55),
        ("moving-factory", 17),
        ("split-decision", 65),
        ("formation-parade", 12),
        ("closing-circle", 240),
        ("nest-circuit", 24),
        ("same-problem-assault-rifle", 61),
        ("same-problem-shotgun", 61),
        ("same-problem-gauss-gun", 61),
    ],
)
def test_example_library_compiles_within_native_limits(name, entries, seed):
    source = example_source(name)
    plan = compile_quest(source, seed=seed)
    assert len(plan.entries) == entries
    assert plan == compile_quest(source, seed=seed)
    assert all(a.trigger_ms <= b.trigger_ms for a, b in zip(plan.entries, plan.entries[1:], strict=False))


def test_crosswind_preserves_alternating_pressure_and_explicit_placement():
    plan = compile_quest(example_source("crosswind"))
    for wave in range(8):
        entries = [entry for entry in plan.entries if entry.trigger_ms == 2000 + wave * 7000]
        plasma = [entry for entry in entries if entry.spawn_id == SpawnId.SPIDER_PLASMA_SHOOTER_3C]
        melee = [entry for entry in entries if entry.spawn_id == SpawnId.SPIDER_SMALL_BLUE_40]
        assert len(plasma) == 2 + wave
        assert len(melee) == 6 + wave
        assert all(entry.count == 1 for entry in entries)
        assert {entry.pos.x for entry in plasma} == ({-64} if wave % 2 == 0 else {1088})
        assert {entry.pos.x for entry in melee} == ({1088} if wave % 2 == 0 else {-64})
        assert sum(entry.pos.y for entry in plasma) / len(plasma) == 512


def test_closing_circle_keeps_a_rotating_escape_gap():
    plan = compile_quest(example_source("closing-circle"))
    previous_angle = None
    for wave in range(12):
        points = [entry.pos for entry in plan.entries if entry.trigger_ms == 2000 + wave * 5000]
        angles = sorted(math.atan2(point.y - 512, point.x - 512) % math.tau for point in points)
        gaps = [angles[i + 1] - angles[i] for i in range(len(angles) - 1)]
        gaps.append(angles[0] + math.tau - angles[-1])
        assert max(gaps) == pytest.approx(math.radians(60), abs=1e-6)
        first_angle = math.atan2(points[0].y - 512, points[0].x - 512)
        if previous_angle is not None:
            assert (first_angle - previous_angle) % math.tau == pytest.approx(math.radians(30), abs=1e-6)
        previous_angle = first_angle


def test_weapon_variants_preserve_the_encounter():
    plans = [
        compile_quest(example_source(f"same-problem-{weapon}")) for weapon in ("assault-rifle", "shotgun", "gauss-gun")
    ]
    assert len({plan.start_weapon_id for plan in plans}) == 3
    assert all(plan.entries == plans[0].entries for plan in plans)
    assert all(plan.terrain_slots == plans[0].terrain_slots for plan in plans)


def test_shuffle_preserves_input_and_is_seeded():
    source = """quest "Shuffle" version 1
let original = [100, 200, 300, 400, 500, 600]
let shuffled = shuffle(original)
repeat 6 as i:
    at 1s:
        spawn alien.small_gray at point(original[i], 100)
    at 2s:
        spawn alien.small_gray at point(shuffled[i], 100)
"""
    plan = compile_quest(source, seed=1)
    original = [entry.pos.x for entry in plan.entries[:6]]
    shuffled = [entry.pos.x for entry in plan.entries[6:]]
    assert original == [100, 200, 300, 400, 500, 600]
    assert sorted(shuffled) == original
    assert shuffled != original
    assert plan.entries != compile_quest(source, seed=2).entries


@pytest.mark.parametrize(
    "expression",
    [
        'edge_line("west", 5000, 20)',
        "arc(center, 100, 0, 90deg, 5000)",
        "shuffle(range(5000))",
    ],
)
def test_example_helpers_reject_oversized_collections(expression):
    with pytest.raises(QuestCompileError, match="collection limit"):
        compile_quest('quest "Too large" version 1\nlet points = ' + expression)


def test_arc_endpoints_singletons_and_position_only_rotation():
    plan = compile_quest("""quest "Geometry" version 1
let original = line(point(100, 200), point(10, 0), 3)
at 1s:
    place alien.small_gray on rotate(original, 90deg, around=point(100, 200))
at 2s:
    place alien.small_gray on original
at 3s:
    place alien.small_gray on arc(center, 100, 0, 90deg, 2)
    place alien.small_gray on arc(center, 100, 0, 90deg, 1)
    place alien.small_gray on arc(center, 100, 0, 90deg, 0)
""")
    assert [(entry.pos.x, entry.pos.y) for entry in plan.entries[:3]] == [(100, 200), (100, 210), (100, 220)]
    assert [(entry.pos.x, entry.pos.y) for entry in plan.entries[3:6]] == [(100, 200), (110, 200), (120, 200)]
    assert [(entry.pos.x, entry.pos.y) for entry in plan.entries[6:]] == [(612, 512), (512, 612), (612, 512)]
    assert all(entry.heading == 0 for entry in plan.entries)
