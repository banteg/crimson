"""crimson-core's diffs match the recovered sources exactly once, and its guard ledger classifies every guard between
builds, without compiling anything."""

import importlib
import json
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
