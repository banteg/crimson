"""crimson-core's diffs match the recovered sources exactly once, its guard ledger classifies every guard between
builds, and every target defines the rules the sources name, without compiling anything (the rules only preprocess)."""

import importlib
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_every_hunk_matches_its_source_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    # The game applies every verifier diff first, in the verifier's order, so its hunks cover both targets.
    game = importlib.import_module("game")

    if stale := adapter.stale_hunks(ROOT, adapter.load_diffs(game.GAME_DIFFS)):
        pytest.fail("\n".join(stale), pytrace=False)


def test_every_guard_between_builds_is_a_branch_or_classified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    targets = adapter.guard_targets(ROOT)

    # Each target reads its sources after its own diffs.
    for hunks, sources in targets:
        try:
            adapter.check_guards(ROOT, hunks, sources)
        except SystemExit as audit:
            pytest.fail(str(audit), pytrace=False)
    if stale := adapter.stale_guards(ROOT, targets):
        pytest.fail(
            f"Guards the ledger lists but no target compiles; rewrite it with {adapter.RECORD_GUARDS}:\n"
            + "\n".join(f"{rel} {key} ({cls})" for rel, key, cls in stale),
            pytrace=False,
        )


def test_recording_guards_classifies_only_new_copies_of_a_listed_guard(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    guard = "#if CL_BUILD == 10908\n    one();\n#else\n    other();\n#endif\n"
    (tmp_path / "guarded.cpp").write_text(guard * 3)
    (tmp_path / "other.cpp").write_text(guard)
    targets = [({}, ["guarded.cpp", "other.cpp"])]
    copies, [single] = adapter.guards(tmp_path, *targets[0]).values()
    first, second, third = copies
    ledger = tmp_path / "guards.json"
    listed = {"guarded.cpp": dict.fromkeys([first, second], "codegen"), "other.cpp": {single: "nan"}}
    ledger.write_text(json.dumps({"classes": dict.fromkeys(["codegen", "layout", "nan"], ""), "guards": listed}))
    monkeypatch.setattr(adapter, "GUARDS", ledger)

    # The third copy starts at line 11.
    with pytest.raises(SystemExit, match=rf"guarded\.cpp:11 \(hash {first}\)"):
        adapter.record_guards(tmp_path, targets, {})
    # The hash's class goes to the new copy alone; the copies the ledger lists, in either file, keep theirs.
    adapter.record_guards(tmp_path, targets, {first: "layout"})
    assert json.loads(ledger.read_text())["guards"] == {
        "guarded.cpp": {first: "codegen", second: "codegen", third: "layout"},
        "other.cpp": {single: "nan"},
    }


def test_each_target_defines_the_rules_the_sources_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")

    # The verifier's flags, and the game module's.
    for flags in ([], ["-DCRIMSON_GAME"]):
        adapter.check_rules(ROOT, ["clang++"], flags)


@pytest.mark.parametrize(
    "spell",
    [
        pytest.param(lambda define: f"#ifdef CRIMSON_GAME\n{define}\n#endif", id="for the game alone"),
        pytest.param(lambda define: f"/*\n{define}\n*/", id="in a comment"),
        pytest.param(lambda define: re.sub(r"\(.*\)$", "(CL_BUILD != 10908)", define), id="by build"),
        pytest.param(lambda _: "", id="left out"),
    ],
)
def test_a_rule_the_port_leaves_to_the_build_stops_the_verifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    spell,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    named = re.findall(r"#define (CL_\w+)", (ROOT / adapter.CL_RULES).read_text())
    rules = tmp_path / "rules.h"
    rules.write_text(
        re.sub(
            rf"^#define (?:{'|'.join(named)})\b.*$",
            lambda m: spell(m[0]),
            adapter.RULES.read_text(),
            flags=re.MULTILINE,
        ),
    )

    with pytest.raises(SystemExit, match="CL_JINXED_RESPECTS_FREEZE"):
        adapter.check_rules(ROOT, ["clang++"], [], rules)


def test_a_rule_cl_rules_defines_over_the_port_stops_the_verifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    include = tmp_path / adapter.CL_RULES
    include.parent.mkdir(parents=True)
    (include.parent / "cl_build.h").write_text((ROOT / include.parent.relative_to(tmp_path) / "cl_build.h").read_text())
    # Without its #ifndef, the default replaces the definition build.py includes first.
    include.write_text(re.sub(r"^#ifndef CL_\w+\n(#define .*\n)#endif\n", r"\1", (ROOT / adapter.CL_RULES).read_text(), flags=re.MULTILINE))

    with pytest.raises(SystemExit, match="CL_JINXED_RESPECTS_FREEZE"):
        adapter.check_rules(tmp_path, ["clang++"], [])


def test_a_rule_defined_outside_cl_rules_is_found_over_continued_lines_and_not_in_comments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")

    text = "#define JINXED_RESPECTS_FREEZE \\\n    (CL_BUILD != 10908)\n#define PISTOL 0x01 // as CL_BUILD 10993 has it\n"
    assert adapter.rule_definitions(text) == ["JINXED_RESPECTS_FREEZE"]
