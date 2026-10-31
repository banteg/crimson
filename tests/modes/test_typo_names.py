from __future__ import annotations

from pathlib import Path

import msgspec
import pytest

from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.modes.typo_mode import TypoShooterMode
from crimson.persistence.highscores import HighScoreRecord, ScoreTable, append_highscore_records
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from crimson.typo.names import (
    NAME_MAX_CHARS,
    CreatureNameTable,
    TypoHighscoreNames,
    load_typo_highscore_names,
    typo_build_name,
)
from grim.rand import Crand
from grim.view import ViewContext
from tests.support.helpers import ScriptedCrand


def test_creature_name_table_assign_random_unique_and_bounded() -> None:
    table = CreatureNameTable.sized(32)
    active = [True] * 32
    rng = Crand(0x1234)

    for idx in range(20):
        name = table.assign_random(
            idx, rng, score_xp=130, active_mask=active, highscore_names=TypoHighscoreNames(loaded=True),
        )
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
        highscore_names=TypoHighscoreNames(loaded=True),
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


def test_typo_build_name_uses_highscore_names_when_highscore_branch_hits() -> None:
    rng = ScriptedCrand([5, 1], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(
        rng,
        score_xp=130,
        highscore_names=TypoHighscoreNames(names=("alpha", "beta"), loaded=True),
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
        highscore_names=TypoHighscoreNames(loaded=True),
    )

    assert name == "quickbrownfox"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_HIGHSCORE_GATE,
    ]


def test_first_highscore_name_pick_loads_the_score_table() -> None:
    # `highscore_load_table` resets its read record and 100 rows, a random tag each, then the pick draws.
    names = TypoHighscoreNames(names=("alpha", "beta"))
    rng = ScriptedCrand([5, *([0] * 101), 1, 5, 0], fallback=ScriptedCrand.Fallback.RAISE)

    first = typo_build_name(rng, score_xp=130, highscore_names=names)
    second = typo_build_name(rng, score_xp=130, highscore_names=names)

    assert (first, second, names.loaded) == ("beta", "alpha", True)
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_HIGHSCORE_GATE,
        RngCallerStatic.HIGHSCORE_LOAD_TABLE_READ_RECORD_RANDOM_TAG,
        *[RngCallerStatic.HIGHSCORE_LOAD_TABLE_ROW_RANDOM_TAG] * 100,
        RngCallerStatic.TYPO_WORD_PICK_HIGHSCORE_NAME,
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_HIGHSCORE_GATE,
        RngCallerStatic.TYPO_WORD_PICK_HIGHSCORE_NAME,
    ]


def test_typo_build_name_tags_exact_four_word_branch_callers() -> None:
    rng = ScriptedCrand([10, 79, 0, 1, 2, 39], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(rng, score_xp=130, highscore_names=TypoHighscoreNames(loaded=True))

    assert name == "nerdheadgunlamb"
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

    name = typo_build_name(rng, score_xp=81, highscore_names=TypoHighscoreNames(loaded=True))

    assert name == "headgunlamb"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_THREE_WORD_GATE_GT80,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
    ]


def test_typo_build_name_tags_exact_two_word_gt40_branch_callers() -> None:
    rng = ScriptedCrand([79, 0, 1], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo_build_name(rng, score_xp=41, highscore_names=TypoHighscoreNames(loaded=True))

    assert name == "gunlamb"
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_TWO_WORD_GATE_GT40,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
    ]


def test_load_typo_highscore_names_filters_and_deduplicates(tmp_path: Path) -> None:
    names = ("Alpha", "Alpha", "Beta.Test", "bad name", "123", "")
    append_highscore_records(tmp_path, [HighScoreRecord(name=name, game_mode_id=GameMode.TYPO) for name in names])

    assert load_typo_highscore_names(tmp_path, ScoreTable(GameMode.TYPO)) == ["Alpha", "Beta.Test"]


@pytest.mark.usefixtures("headless_resources")
@pytest.mark.parametrize(
    ("cl_build", "names"), [(ClBuild.V1_9_93, ("Alpha", "Beta.Test")), (ClBuild.V1_9_8, ("Gamma",))],
)
def test_typo_mode_open_loads_its_builds_highscore_names_into_state_and_replay_header(
    make_mode_config,
    assets_dir: Path,
    tmp_path: Path,
    cl_build: ClBuild,
    names: tuple[str, ...],
) -> None:
    append_highscore_records(
        tmp_path,
        [HighScoreRecord(name=name, game_mode_id=GameMode.TYPO) for name in ("Alpha", "Beta.Test")]
        + [HighScoreRecord(name="Gamma", game_mode_id=GameMode.TYPO, cl_build=ClBuild.V1_9_8)],
    )

    config = make_mode_config(game_mode=GameMode.TYPO, base_dir=tmp_path)
    mode = TypoShooterMode(ViewContext(assets_dir=assets_dir), config=config, audio_rng=Crand(0xBEEF))
    mode.cl_build = cl_build

    mode.open()

    assert mode.state.typo.highscore_names.names == names
    assert mode._replay_recorder is not None
    assert mode._replay_recorder.run.typo_highscore_names == names


@pytest.mark.usefixtures("headless_resources")
def test_typo_highscore_names_load_once_per_build(make_mode_config, assets_dir: Path, tmp_path: Path) -> None:
    def save(name: str, cl_build: ClBuild) -> None:
        append_highscore_records(tmp_path, [HighScoreRecord(name=name, game_mode_id=GameMode.TYPO, cl_build=cl_build)])

    save("Alpha", ClBuild.V1_9_93)
    save("Gamma", ClBuild.V1_9_8)
    config = make_mode_config(game_mode=GameMode.TYPO, base_dir=tmp_path)
    mode = TypoShooterMode(ViewContext(assets_dir=assets_dir), config=config, audio_rng=Crand(0xBEEF))

    def play(cl_build: ClBuild) -> tuple[tuple[str, ...], bool]:
        """A Typ-o run on `cl_build` that picks a high-score name: the names it picks from, and whether it found them
        loaded."""

        kept = mode.typo_session.carry
        mode.cl_build = cl_build
        mode.open()
        assert mode._replay_recorder is not None
        run = mode._replay_recorder.run
        # Its replay plays it with the names it picks from; the rest of the carry ignores builds.
        assert initialize_run(run).session.world.state.typo.highscore_names == mode.state.typo.highscore_names
        assert msgspec.structs.replace(run.typo_carry, highscore_names_loaded=kept.highscore_names_loaded) == kept
        mode.state.typo.highscore_names.pick(Crand(0))
        mode.typo_session.keep(mode.state.typo)
        return run.typo_highscore_names, run.typo_carry.highscore_names_loaded

    assert play(ClBuild.V1_9_93) == (("Alpha",), False)
    save("Delta", ClBuild.V1_9_93)
    # Another run on the build picks from the names the first loaded.
    assert play(ClBuild.V1_9_93) == (("Alpha",), True)
    # A run on the other build loads its own table, which the next run on that build keeps too.
    assert play(ClBuild.V1_9_8) == (("Gamma",), False)
    save("Zeta", ClBuild.V1_9_8)
    assert play(ClBuild.V1_9_8) == (("Gamma",), True)
    # A run back on the first loads that one afresh.
    assert play(ClBuild.V1_9_93) == (("Alpha", "Delta"), False)


@pytest.mark.parametrize(
    ("cl_build", "expected"),
    [
        # 1.9.93: 41 % 51 is "sleep", 83 % 52 is "brown".
        (ClBuild.V1_9_93, "brownsleep"),
        # 1.9.8's 42 fragments: 41 % 41 is "lamb", 83 % 42 is its last fragment, "the".
        (ClBuild.V1_9_8, "thelamb"),
    ],
)
def test_typo_run_builds_names_from_its_build_fragments(cl_build: ClBuild, expected: str) -> None:
    typo = initialize_run(RunSpec(game_mode_id=GameMode.TYPO, seed=1, cl_build=cl_build)).session.world.state.typo
    rng = ScriptedCrand([79, 41, 83], fallback=ScriptedCrand.Fallback.RAISE)

    name = typo.names.assign_random(
        0, rng, score_xp=41, active_mask=[False] * len(typo.names.names), highscore_names=typo.highscore_names,
    )

    assert name == expected
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TYPO_TARGET_NAME_ASSIGN_RANDOM_TWO_WORD_GATE_GT40,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
        RngCallerStatic.TYPO_WORD_PICK_FRAGMENT,
    ]
