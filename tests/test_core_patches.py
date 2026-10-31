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


# What a recovered source compiles with besides its own headers: the verifier's, and the game module's.
VERIFIER = ["-I", str(ROOT / "crimson-core/host"), "-I", str(ROOT / "third_party/headers")]
GAME = [*VERIFIER, "-DCRIMSON_GAME", "-I", str(ROOT / "crimson-core/game/include")]


def test_each_target_defines_the_rules_the_sources_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")

    for flags in (VERIFIER, GAME):
        adapter.check_rules(ROOT, ["clang++"], flags)


def _by_build(define: str) -> str:
    return re.sub(r"\(.*\)$", "(CL_BUILD != 10908)", define)


@pytest.mark.parametrize(
    "spell",
    [
        pytest.param(lambda define: f"#ifdef CRIMSON_GAME\n{define}\n#endif", id="for the game alone"),
        pytest.param(lambda define: f"/*\n{define}\n*/", id="in a comment"),
        pytest.param(_by_build, id="by build"),
        pytest.param(
            lambda define: re.sub(r"(\w+) \(.*\)$", r"RULE_DEFAULT (CL_BUILD != 10908)\n#define \1 RULE_DEFAULT", define),
            id="through another macro",
        ),
        pytest.param(
            # stdint.h comes before rules.h (host/api.h), so the run's definition never compiles.
            lambda define: f"#ifdef UINT32_MAX\n{_by_build(define)}\n#else\n{define}\n#endif",
            id="behind a header included first",
        ),
        pytest.param(lambda define: re.sub(r" \(.*\)$", "", define), id="as nothing"),
        pytest.param(lambda define: re.sub(r"(\w+) \(", r"\1() (", define), id="as a function"),
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
            (adapter.HOOKS.parent / "rules.h").read_text(),
            flags=re.MULTILINE,
        ),
    )
    hooks = tmp_path / "hooks.h"
    hooks.write_text(adapter.HOOKS.read_text().replace('#include "rules.h"', f'#include "{rules}"'))

    with pytest.raises(SystemExit, match="CL_JINXED_RESPECTS_FREEZE"):
        adapter.check_rules(ROOT, ["clang++"], VERIFIER, hooks)


def _rules_root(tmp_path: Path, adapter, text: str) -> Path:
    header = tmp_path / adapter.CL_RULES
    header.parent.mkdir(parents=True)
    (header.parent / "cl_build.h").write_text((ROOT / adapter.CL_RULES).with_name("cl_build.h").read_text())
    header.write_text(text)
    return tmp_path


def test_a_rule_cl_rules_defines_over_the_port_stops_the_verifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    # Without its #ifndef, the default replaces the definition build.py includes first.
    text = re.sub(r"^#ifndef CL_\w+\n(#define .*\n)#endif\n", r"\1", (ROOT / adapter.CL_RULES).read_text(), flags=re.MULTILINE)

    with pytest.raises(SystemExit, match="CL_JINXED_RESPECTS_FREEZE"):
        adapter.check_rules(_rules_root(tmp_path, adapter, text), ["clang++"], VERIFIER)


def test_a_rule_only_the_game_names_stops_the_game(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    text = (ROOT / adapter.CL_RULES).read_text().replace(
        "\n#endif\n", "\n#ifdef CRIMSON_GAME\n#define CL_GAME_RULE (CL_BUILD != 10908)\n#endif\n\n#endif\n",
    )
    root = _rules_root(tmp_path, adapter, text)

    adapter.check_rules(root, ["clang++"], VERIFIER)
    with pytest.raises(SystemExit, match="CL_GAME_RULE"):
        adapter.check_rules(root, ["clang++"], GAME)


def test_the_tripwire_reads_a_definition_by_build_as_the_preprocessor_does(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")

    text = (
        "#define CONTINUED \\\n    (CL_BUILD != 10908)\n"
        "#define SPLIT (CL_BU\\\nILD != 10908)\n"
        "#define PISTOL 0x01 // as CL_BUILD 10993 has it\n"
        '#define LABEL "CL_BUILD"\n'
        '#define OPEN "/*"\n#define HIDDEN (CL_BUILD != 10908)\n#define CLOSE "*/"\n'
        "#define RANGE (10'908 <= CL_BUILD && CL_BUILD < 10'993)\n"
    )
    assert adapter.rule_definitions(text) == ["CONTINUED", "SPLIT", "HIDDEN", "RANGE"]


def test_a_rule_cl_rules_defines_as_a_function_stops_the_build(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    text = (ROOT / adapter.CL_RULES).read_text().replace(
        "\n#endif\n", "\n#define CL_JINXED_FREEZE_ACTIVE(timer) (CL_BUILD != 10908 && (timer) > 0.0f)\n\n#endif\n",
    )

    with pytest.raises(SystemExit, match="CL_JINXED_FREEZE_ACTIVE"):
        adapter.check_rules(_rules_root(tmp_path, adapter, text), ["clang++"], VERIFIER)
