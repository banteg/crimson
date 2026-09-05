from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from crimson.match_regressions import FunctionMatch, Manifest, apply_waivers, compare_manifests, parse_manifest


def _function(**changes: object) -> FunctionMatch:
    original = FunctionMatch(0x401000, "foo", 100, "match", 1.0, 10, 10, 10, 4, 0, 0, True)
    return replace(original, **changes)


def _manifest(function: FunctionMatch) -> Manifest:
    return Manifest("crimsonland.exe", "port", "a" * 64, (function,))


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        (_function(state="wip", ratio=0.9, body_byte_exact=False), {"exact-lost", "body-byte-exact-lost"}),
        (
            _function(state="audit", unresolved=1, body_byte_exact=False),
            {"exact-lost", "unresolved-increased", "body-byte-exact-lost"},
        ),
        (
            _function(state="audit", mismatches=1, body_byte_exact=False),
            {"exact-lost", "mismatches-increased", "body-byte-exact-lost"},
        ),
        (_function(body_byte_exact=False), {"body-byte-exact-lost"}),
        (_function(target_size=99), {"extent-changed"}),
        (_function(function="renamed"), set()),
    ],
)
def test_regression_gate_preserves_address_keyed_evidence(candidate: FunctionMatch, expected: set[str]) -> None:
    problems, _ = compare_manifests(_manifest(_function()), _manifest(candidate))
    assert {row.check for row in problems} == expected


def test_wip_score_drop_is_reported_without_failing_acceptance_gate() -> None:
    before = _function(state="wip", ratio=0.9, body_byte_exact=False)
    after = replace(before, ratio=0.8, prefix=2)
    problems, deltas = compare_manifests(_manifest(before), _manifest(after))
    assert problems == []
    assert deltas[0].before.ratio == 0.9
    assert deltas[0].after.ratio == 0.8


def test_removed_targets_and_changed_scope_need_explicit_base_bound_reasons() -> None:
    before = _manifest(_function())
    problems, _ = compare_manifests(before, replace(before, scope="all", functions=()))
    assert {row.check for row in problems} == {"scope-changed", "target-removed"}
    payload = {
        "schema": 1,
        "base_commit": "a" * 40,
        "waivers": [
            {"image": row.image, "address": row.address, "check": row.check, "reason": "audited provider ownership"}
            for row in problems
        ],
    }
    assert all(row.waiver for row in apply_waivers(problems, payload, base_commit="a" * 40))
    with pytest.raises(ValueError, match="exact base"):
        apply_waivers(problems, payload, base_commit="b" * 40)
    with pytest.raises(ValueError, match="unused"):
        apply_waivers([], payload, base_commit="a" * 40)
    payload["waivers"][0]["reason"] = " "
    with pytest.raises(ValueError, match="reason"):
        apply_waivers(problems, payload, base_commit="a" * 40)


def test_reference_image_change_is_not_a_comparable_baseline() -> None:
    before = _manifest(_function())
    with pytest.raises(ValueError, match="reference image changed"):
        compare_manifests(before, replace(before, reference_sha256="b" * 64))


def test_parser_rejects_duplicate_functions_and_inconsistent_states() -> None:
    row = {
        "address": 0x401000,
        "function": "foo",
        "target_size": 10,
        "match": {
            "state": "match",
            "ratio": 1.0,
            "masked_ok": 1,
            "masked_unresolved": 0,
            "masked_mismatches": 0,
            "prefix_instructions": 2,
            "target_instructions": 2,
            "candidate_instructions": 2,
        },
    }
    payload = {
        "kind": "crimson-native-object-manifest",
        "schema": 2,
        "image": "crimsonland.exe",
        "scope": "port",
        "reference_image_sha256": "a" * 64,
        "function_count": 1,
        "objects": [{"functions": [row]}],
    }
    # Historical manifests predate the byte identity field.
    assert parse_manifest(payload).functions[0].body_byte_exact is None
    row["match"]["masked_mismatches"] = 1
    with pytest.raises(ValueError, match="inconsistent"):
        parse_manifest(payload)
    row["match"]["masked_mismatches"] = 0
    payload["objects"][0]["functions"].append(row)
    with pytest.raises(ValueError, match="duplicate function"):
        parse_manifest(payload)


def test_regression_cli_reads_git_base_and_fails_current_exact_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json
    import shutil
    import subprocess

    from typer.testing import CliRunner

    from crimson.cli.match import match_app

    git = shutil.which("git")
    assert git is not None
    root = tmp_path
    manifest = {
        "kind": "crimson-native-object-manifest",
        "schema": 2,
        "image": "crimsonland.exe",
        "scope": "port",
        "reference_image_sha256": "a" * 64,
        "function_count": 1,
        "objects": [
            {
                "functions": [
                    {
                        "address": 0x401000,
                        "function": "foo",
                        "target_size": 10,
                        "match": {
                            "ratio": 1.0,
                            "state": "match",
                            "masked_ok": 1,
                            "masked_unresolved": 0,
                            "masked_mismatches": 0,
                            "prefix_instructions": 2,
                            "target_instructions": 2,
                            "candidate_instructions": 2,
                        },
                    },
                ],
            },
        ],
    }
    for image in ("crimsonland.exe", "grim.dll"):
        path = root / "analysis/native" / image / "objects.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({**manifest, "image": image}))
    subprocess.run([git, "init", "-q", str(root)], check=True)
    subprocess.run([git, "add", "analysis"], cwd=root, check=True)
    subprocess.run(
        [git, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "test: baseline"],
        cwd=root,
        check=True,
    )
    monkeypatch.setattr("crimson.cli.match.matchlib.REPO_ROOT", root)
    runner = CliRunner()
    assert runner.invoke(match_app, ["regressions", "--base", "HEAD"]).exit_code == 0
    manifest["objects"][0]["functions"][0]["match"].update(ratio=0.9, state="wip")
    (root / "analysis/native/crimsonland.exe/objects.json").write_text(json.dumps(manifest))
    result = runner.invoke(match_app, ["regressions", "--base", "HEAD", "--json"])
    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["regressions"][0]["check"] == "exact-lost"
    base = json.loads(result.output)["base_commit"]
    waivers = root / "tools/match/regression-waivers.json"
    waivers.parent.mkdir(parents=True)
    waivers.write_text(
        json.dumps(
            {
                "schema": 1,
                "base_commit": base,
                "waivers": [
                    {
                        "image": "crimsonland.exe",
                        "address": 0x401000,
                        "check": "exact-lost",
                        "reason": "reviewed correction",
                    },
                ],
            },
        ),
    )
    result = runner.invoke(match_app, ["regressions"])
    assert result.exit_code == 0, result.output
    assert "waived: reviewed correction" in result.output
