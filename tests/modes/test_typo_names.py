from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import crimson.modes.base_gameplay_mode as base_gameplay_mode
import crimson.world.render_resources as render_resources_module
from crimson.game_modes import GameMode
from crimson.modes.typo_mode import TypoShooterMode
from crimson.persistence.highscores import HighScoreRecord, scores_path_for_mode, write_highscore_records
from crimson.rng_caller_static import RngCallerStatic
from crimson.typo.names import NAME_MAX_CHARS, CreatureNameTable, load_typo_highscore_names, typo_build_name
from grim.rand import Crand
from grim.view import ViewContext
from tests.support.helpers import ScriptedCrand


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def test_creature_name_table_assign_random_unique_and_bounded() -> None:
    table = CreatureNameTable.sized(32)
    active = [True] * 32
    rng = Crand(0x1234)

    for idx in range(20):
        name = table.assign_random(idx, rng, score_xp=130, active_mask=active)
        assert name
        assert len(name) < NAME_MAX_CHARS

    assert len(set(table.names[:20])) == 20


def test_creature_name_table_allows_native_long_name_retry_count(mocker) -> None:
    table = CreatureNameTable.sized(1)
    build_name = mocker.patch(
        "crimson.typo.names.typo_build_name",
        return_value="abcdefghijklmnop",
    )

    name = table.assign_random(
        0,
        Crand(1),
        score_xp=0,
        active_mask=[False],
    )

    assert name == "abcdefghijklmnop"
    assert build_name.call_count == 101


def test_creature_name_table_find_by_name_active_only() -> None:
    table = CreatureNameTable.sized(4)
    table.names[0] = "alpha"
    table.names[1] = "beta"
    table.names[2] = "gamma"

    assert table.find_by_name("beta", active_mask=[True, True, True, True]) == 1
    assert table.find_by_name("beta", active_mask=[True, False, True, True]) is None
    assert table.find_by_name("missing", active_mask=[True, True, True, True]) is None


def test_creature_name_table_clear_removes_name() -> None:
    table = CreatureNameTable.sized(3)
    table.names[1] = "beta"
    table.clear(1)
    assert table.names[1] == ""


def test_typo_build_name_uses_highscore_names_when_highscore_branch_hits() -> None:
    rng = ScriptedCrand([5, 1], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(
        rng,
        score_xp=130,
        highscore_names=("alpha", "beta"),
    )

    assert name == "beta"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_HIGHSCORE_GATE,
        RngCallerStatic.TYPO_WORD_PICK_HIGHSCORE_NAME,
    ]


def test_typo_build_name_falls_back_to_quickbrownfox_without_highscore_names() -> None:
    rng = ScriptedCrand([5], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(
        rng,
        score_xp=130,
        highscore_names=(),
    )

    assert name == "quickbrownfox"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_HIGHSCORE_GATE,
    ]


def test_typo_build_name_tags_exact_four_word_branch_callers() -> None:
    rng = ScriptedCrand([10, 79, 0, 1, 2, 39], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(rng, score_xp=130)

    assert name == "lambgunheadnerd"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_HIGHSCORE_GATE,
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_FOUR_WORD_GATE,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
    ]


def test_typo_build_name_tags_exact_three_word_gt80_branch_callers() -> None:
    rng = ScriptedCrand([79, 0, 1, 2], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(rng, score_xp=81)

    assert name == "lambgunhead"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_THREE_WORD_GATE_GT80,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
    ]


def test_typo_build_name_tags_exact_three_word_gt60_branch_callers() -> None:
    rng = ScriptedCrand([39, 0, 1, 2], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(rng, score_xp=61)

    assert name == "lambgunhead"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_THREE_WORD_GATE_GT60,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
    ]


def test_typo_build_name_tags_exact_two_word_gt40_branch_callers() -> None:
    rng = ScriptedCrand([79, 0, 1], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(rng, score_xp=41)

    assert name == "lambgun"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_TWO_WORD_GATE_GT40,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
    ]


def test_typo_build_name_tags_exact_two_word_gt20_branch_callers() -> None:
    rng = ScriptedCrand([39, 0, 1], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(rng, score_xp=21)

    assert name == "lambgun"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_TWO_WORD_GATE_GT20,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
    ]


def test_load_typo_highscore_names_filters_and_deduplicates(tmp_path: Path) -> None:
    path = scores_path_for_mode(tmp_path, GameMode.TYPO)
    records = []
    for value in ("Alpha", "Alpha", "Beta.Test", "bad name", "123", ""):
        record = HighScoreRecord.blank()
        record.set_name(value)
        record.game_mode_id = GameMode.TYPO
        records.append(record)
    write_highscore_records(path, records)

    assert load_typo_highscore_names(path) == ["Alpha", "Beta.Test"]


def test_typo_mode_open_loads_highscore_names_into_state_and_replay_header(mocker, make_mode_config, tmp_path: Path) -> None:
    path = scores_path_for_mode(tmp_path, GameMode.TYPO)
    records = []
    for value in ("Alpha", "Beta.Test"):
        record = HighScoreRecord.blank()
        record.set_name(value)
        record.game_mode_id = GameMode.TYPO
        records.append(record)
    write_highscore_records(path, records)

    config = make_mode_config(game_mode=GameMode.TYPO, base_dir=tmp_path)
    mode = TypoShooterMode(ViewContext(assets_dir=_assets_dir()), config=config, audio_rng=Crand(0xBEEF))
    mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
    resources = SimpleNamespace(texture=lambda _texture_id: object())
    small_font = SimpleNamespace(cell_size=10)
    mocker.patch.object(render_resources_module, "runtime_resources_for", return_value=resources)
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=small_font)

    mode.open()

    assert mode.state.typo.highscore_names == ("Alpha", "Beta.Test")
    assert mode._replay_recorder is not None
    assert mode._replay_recorder.header.typo_highscore_names == ("Alpha", "Beta.Test")
