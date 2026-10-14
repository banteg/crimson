"""A custom quest's run reaches the core's stream with the one table it plays, and the gate reads it back."""

import importlib.util
from importlib.resources import files
from pathlib import Path

import msgspec
import pytest

from crimson.quests.dsl import build_custom_quest
from crimson.replay import load_replay

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch):
    checks = ROOT / "crimson-core/checks"
    monkeypatch.syspath_prepend(str(checks))
    spec = importlib.util.spec_from_file_location("core_gate", checks / "gate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_custom_quest_stream_carries_the_table_and_restrictions_its_run_plays(gate) -> None:
    quest = build_custom_quest(files("crimson.quests.dsl").joinpath("examples", "same-problem-shotgun.quest").read_text())
    replay = load_replay((ROOT / "tests/fixtures/replays/quest-1.1-completed.crd").read_bytes())
    run = msgspec.structs.replace(replay.run, quest_level=None, custom_quest=quest, hardcore=False)
    stream = gate.Stream("custom.rsi", gate.encode(msgspec.structs.replace(replay, run=run), None))

    assert stream.config[1:4] == (3, 0, 0)
    assert stream.ticks == replay.ticks
    spec = stream.run_spec()
    assert spec.quest_level is None and spec.custom_quest is not None
    assert spec.custom_quest.entries == quest.entries
    assert (
        spec.custom_quest.start_weapon_id,
        spec.custom_quest.terrain_slots,
        spec.custom_quest.no_bonuses,
        spec.custom_quest.no_perks,
        spec.custom_quest.no_weapons,
    ) == (
        quest.start_weapon_id,
        quest.terrain_slots,
        quest.no_bonuses,
        quest.no_perks,
        quest.no_weapons,
    )
