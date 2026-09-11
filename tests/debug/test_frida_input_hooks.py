import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
AGENT = ROOT / "scripts/frida/gameplay_diff_capture.js"
HARNESS = ROOT / "tools/match/evidence/player-input-capture-2026-09-11/harness.js"


def _run(body: str) -> dict:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the Frida input callbacks")
    script = (
        f"const {{createInputHarness}} = require({json.dumps(str(HARNESS))});\n"
        f"const source = require('node:fs').readFileSync({json.dumps(str(AGENT))}, 'utf8');\n"
        + body
    )
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_filtered_nested_queries_preserve_primary_helper_context() -> None:
    result = _run("""
const h = createInputHarness(source);
const outer = h.begin("input_primary_just_pressed", 0x440000, 0);
const active = h.begin("grim_is_key_active", 0x446052, 104);
const down = h.begin("grim_is_key_down", 0x100071a2, 104);
h.leave(down, 1);
h.leave(active, 1);
h.leave(outer, 1);
console.log(JSON.stringify(h.snapshot()));
""")
    assert result["contexts"] == {}
    assert result["keys"][0]["fire_pressed"]
    assert not result["keys"][0]["fire_down"]
    assert [row[0] for row in result["queries"]] == ["primary_edge"]
    assert [row["query"] for row in result["events"]] == ["input_primary_just_pressed"]


def test_tracked_nesting_and_interleaved_threads_keep_distinct_results() -> None:
    result = _run("""
const h = createInputHarness(source);
const outer = h.begin("grim_is_key_active", 0x414000, 104, 1);
const nested = h.begin("grim_is_key_down", 0x414004, 90, 1);
const other = h.begin("grim_is_key_active", 0x414008, 105, 2);
h.leave(nested, 1);
const filtered = h.begin("grim_is_key_down", 0x100071a2, 104, 1);
h.leave(filtered, 1);
h.leave(outer, 0);
h.leave(other, 1);
console.log(JSON.stringify(h.snapshot()));
""")
    assert result["contexts"] == {}
    assert not result["keys"][0]["fire_down"]
    assert result["keys"][1]["fire_down"]
    assert all(row["reload_down"] for row in result["keys"])


@pytest.mark.parametrize("name", [
    "grim_is_key_down", "grim_is_key_active", "input_primary_just_pressed",
    "input_any_key_pressed",
])
@pytest.mark.parametrize("low_byte", [0, 1, 255])
def test_query_results_use_the_native_boolean_byte(name: str, low_byte: int) -> None:
    result = _run(f"""
const h = createInputHarness(source);
const call = h.begin({json.dumps(name)}, 0x414000, 104);
h.leave(call, {0xDEAD0000 | low_byte});
console.log(JSON.stringify(h.snapshot()));
""")
    if name.startswith("grim_"):
        assert result["keys"][0]["fire_down"] == bool(low_byte)
    elif name == "input_primary_just_pressed":
        assert result["keys"][0]["fire_pressed"] == bool(low_byte)
    else:
        assert result["queries"][0][1] == bool(low_byte)


@pytest.mark.parametrize("value", [0, 1, 0x100])
def test_integer_query_result_keeps_its_full_width(value: int) -> None:
    result = _run(f"""
const h = createInputHarness(source);
const call = h.begin("input_primary_is_down", 0x440000, 0);
h.leave(call, {value});
console.log(JSON.stringify(h.snapshot()));
""")
    assert result["keys"][0]["fire_down"] == bool(value)


@pytest.mark.parametrize("player_index", [0, 1])
@pytest.mark.parametrize("held_g", [False, True])
def test_accepted_shot_captures_effective_fire_for_its_player(player_index: int, held_g: bool) -> None:
    result = _run(f"""
const h = createInputHarness(source, {{playerIndex: {player_index}, aimScheme: 5}});
h.query({{name: "grim_is_key_active", key: 104, caller: 0x415c00, result: 0}});
h.query({{name: "grim_is_key_active", key: 34, caller: 0x415cee, result: {int(held_g)}}});
// A later physical false query must not erase the native accepted-shot evidence.
h.query({{name: "grim_is_key_active", key: 104, caller: 0x415c00, result: 0}});
console.log(JSON.stringify(h.snapshot()));
""")
    assert result["errors"] == []
    assert result["contexts"] == {}
    for index, row in enumerate(result["keys"]):
        assert row["fire_down"] == (index == player_index)
        assert row["fire_bullets_key_down"] == held_g
        assert result["inputs"][index][4] & 1 == int(index == player_index)
        assert bool(result["inputs"][index][4] & (1 << 17)) == held_g


@pytest.mark.parametrize("name,key,caller", [
    ("grim_is_key_down", 34, 0x415CEE),
    ("grim_is_key_active", 34, 0x415CEF),
    ("grim_is_key_active", 35, 0x415CEE),
    ("grim_is_key_active", 34, 0x100071A2),
])
def test_unrelated_query_or_projectile_is_not_effective_fire(name: str, key: int, caller: int) -> None:
    result = _run(f"""
const h = createInputHarness(source, {{projectileCounts: [8, 8]}});
h.query({{name: {json.dumps(name)}, key: {key}, caller: {caller}, result: 1}});
console.log(JSON.stringify(h.snapshot()));
""")
    assert not any(row["fire_down"] for row in result["keys"])
    assert all((row[4] & 1) == 0 for row in result["inputs"])


@pytest.mark.parametrize("player_index", [None, -1, 2, 1.5])
def test_invalid_fire_gate_owner_invalidates_capture(player_index: float | None) -> None:
    result = _run(f"""
const h = createInputHarness(source);
h.env.activePlayer = {json.dumps(player_index)};
const call = h.begin("grim_is_key_active", 0x415cee, 34);
h.leave(call, 0);
console.log(JSON.stringify(h.snapshot()));
""")
    assert result["errors"] == ["player_fire_gate_invalid_player_index"]
    assert not any(row["fire_down"] for row in result["keys"])
    assert result["contexts"] == {}
