from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match_experiments import (
    build_mutation_error_audit,
    mutation_error_evidence_sha256,
    summarize_experiments,
)


def _result(
    source: str,
    fuzzy_delta: float,
    *,
    prefix_delta: int = 0,
    mismatch_delta: int = 0,
) -> dict[str, Any]:
    return {
        "source_sha256": source,
        "status": {
            "compiler": "msvc6.5",
            "cflags": "/O2",
            "candidate_instructions": 11 if fuzzy_delta > 0 else 10,
            "target_instructions": 10,
        },
        "delta": {
            "fuzzy_weighted_bytes": fuzzy_delta,
            "prefix_instructions": prefix_delta,
            "first_mismatch": {
                "baseline_target_offset": 32,
                "probe_target_offset": 16 if prefix_delta < 0 else 32,
            },
            "references": {
                "ok": -1 if mismatch_delta else 0,
                "unresolved": 0,
                "mismatch": mismatch_delta,
            },
        },
    }


def _sweep(
    spec: str,
    results: list[dict[str, Any]],
    *,
    improves: bool = False,
    exact: bool = False,
) -> dict[str, Any]:
    winner = (
        {
            **results[0],
            "status": {
                **results[0]["status"],
                "state": "match" if exact else "wip",
            },
        }
        if improves
        else None
    )
    return {
        "schema": 1,
        "kind": "mutation-sweep",
        "recorded_at": "2026-07-27T00:00:00+00:00",
        "spec_sha256": spec,
        "possible_variants": len(results),
        "planned_variants": len(results),
        "evaluated_variants": len(results),
        "combinations_never_evaluated": 0,
        "truncated": False,
        "stop_reason": None,
        "best_improves": improves,
        "winner": winner,
        "baseline": {
            "function": "foo",
            "image": "crimsonland.exe",
            "candidate_instructions": 10,
            "target_instructions": 10,
        },
        "results": results,
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


def test_experiment_summary_surfaces_repeats_stalls_and_tradeoffs(
    tmp_path: Path,
) -> None:
    log = tmp_path / "scratches" / "foo" / "experiments.jsonl"
    records: list[dict[str, Any]] = [
        _sweep("spec-a", [_result("variant-a", 0), _result("variant-b", -2)]),
        _sweep("spec-a", [_result("variant-a", 0)]),
        _sweep(
            "spec-b",
            [_result("variant-c", 5, prefix_delta=-1, mismatch_delta=1)],
            improves=True,
            exact=True,
        ),
        {
            "baseline": {"function": "foo", "image": "crimsonland.exe"},
            "probe": {"state": "wip"},
            "delta": {"fuzzy_weighted_bytes": 1},
        },
    ]
    _write_jsonl(log, records)

    payload = summarize_experiments(tmp_path)

    assert payload["summary"] == {
        "files": 1,
        "records": 4,
        "current_records": 4,
        "historical_records": 0,
        "unversioned_records": 4,
        "kinds": {"mutation-sweep": 3, "probe": 1},
        "evaluated_variants": 4,
        "unique_variants": 3,
        "repeated_variants": 1,
        "improving_variants": 1,
        "neutral_variants": 2,
        "degrading_variants": 1,
        "errored_variants": 0,
        "tradeoff_variants": 1,
        "improving_sweeps": 1,
        "improving_probes": 1,
        "exact_winners": 1,
        "stalled_scratches": 0,
        "current_inconclusive_sweeps": 0,
        "current_errored_variants": 0,
        "audited_errored_variants": 0,
        "mutation_error_audits": 0,
        "errors": 0,
        "strict_errors": 0,
    }
    row = payload["rows"][0]
    assert row["scratch"] == "scratches/foo"
    assert row["repeated_spec_runs"] == 1
    assert row["no_improvement_streak"] == 0
    assert row["flags"] == [
        "repeated-variants",
        "repeated-specs",
        "metric-tradeoffs",
    ]


def test_experiment_summary_check_rejects_malformed_logs(tmp_path: Path) -> None:
    log = tmp_path / "scratches" / "stalled" / "experiments.jsonl"
    _write_jsonl(
        log,
        [_sweep(f"spec-{index}", [_result(f"variant-{index}", 0)]) for index in range(3)],
    )
    with log.open("a", encoding="utf-8") as handle:
        handle.write("{not-json}\n")

    completed = CliRunner().invoke(
        match_app,
        [
            "experiments",
            "--match-root",
            str(tmp_path),
            "--sort",
            "no-improvement",
            "--check",
            "--json",
        ],
    )

    assert completed.exit_code == 1
    payload = json.loads(completed.output)
    assert payload["summary"]["stalled_scratches"] == 0
    assert payload["summary"]["errors"] == 1
    assert payload["rows"][0]["flags"] == ["historical-only", "malformed"]


def test_experiment_summary_separates_variant_errors_from_regressions(
    tmp_path: Path,
) -> None:
    log = tmp_path / "scratches" / "failed" / "experiments.jsonl"
    failed = _result("variant-failed", -10)
    failed["status"]["state"] = "error"
    _write_jsonl(log, [_sweep("spec-failed", [failed])])

    payload = summarize_experiments(tmp_path)

    assert payload["summary"]["evaluated_variants"] == 1
    assert payload["summary"]["degrading_variants"] == 0
    assert payload["summary"]["errored_variants"] == 1
    assert payload["rows"][0]["flags"] == ["variant-errors", "inconclusive-sweeps"]
    assert payload["summary"]["strict_errors"] == 1

    sorted_payload = summarize_experiments(tmp_path, sort_by="errors")
    assert sorted_payload["rows"][0]["errored_variants"] == 1


def test_only_complete_current_epoch_sweeps_can_mark_a_scratch_stalled(
    tmp_path: Path,
) -> None:
    log = tmp_path / "scratches" / "epoch" / "experiments.jsonl"
    old_epoch = "a" * 64
    current_epoch = "b" * 64
    historical = [
        {"baseline_epoch": old_epoch, **_sweep(f"old-{index}", [_result(f"old-{index}", 0)])}
        for index in range(3)
    ]
    incomplete = {
        "baseline_epoch": current_epoch,
        **_sweep("current-incomplete", [_result("current-incomplete", 0)]),
        "possible_variants": 2,
        "truncated": True,
        "stop_reason": "variant-budget",
    }
    _write_jsonl(log, [*historical, incomplete])

    payload = summarize_experiments(
        tmp_path,
        current_epochs={log.parent.resolve(): current_epoch},
    )

    row = payload["rows"][0]
    assert row["current_records"] == 1
    assert row["historical_records"] == 3
    assert row["no_improvement_streak"] == 0
    assert row["current_inconclusive_sweeps"] == 1
    assert "stalled" not in row["flags"]

    complete = [
        {
            "baseline_epoch": current_epoch,
            **_sweep(f"current-{index}", [_result(f"current-{index}", 0)]),
        }
        for index in range(3)
    ]
    _write_jsonl(log, [*historical, *complete])

    payload = summarize_experiments(
        tmp_path,
        current_epochs={log.parent.resolve(): current_epoch},
    )
    assert payload["rows"][0]["no_improvement_streak"] == 3
    assert "stalled" in payload["rows"][0]["flags"]


def test_strict_errors_only_apply_to_the_current_baseline_epoch(
    tmp_path: Path,
) -> None:
    log = tmp_path / "scratches" / "failed_epoch" / "experiments.jsonl"
    failed = _result("failed", -1)
    failed["status"]["state"] = "error"
    old_epoch = "a" * 64
    current_epoch = "b" * 64
    _write_jsonl(
        log,
        [{"baseline_epoch": old_epoch, **_sweep("failed", [failed])}],
    )

    historical = summarize_experiments(
        tmp_path,
        current_epochs={log.parent.resolve(): current_epoch},
    )
    assert historical["summary"]["errored_variants"] == 1
    assert historical["summary"]["current_errored_variants"] == 0
    assert historical["strict_errors"] == []

    current = summarize_experiments(
        tmp_path,
        current_epochs={log.parent.resolve(): old_epoch},
    )
    assert current["summary"]["current_errored_variants"] == 1
    assert len(current["strict_errors"]) == 1


def test_audited_invalid_plan_errors_remain_inconclusive_but_not_strict(
    tmp_path: Path,
) -> None:
    log = tmp_path / "scratches" / "audited" / "experiments.jsonl"
    current_epoch = "b" * 64
    failed = _result("failed", -1)
    failed["status"]["state"] = "error"
    _write_jsonl(
        log,
        [{"baseline_epoch": current_epoch, **_sweep("failed", [failed])}],
    )
    audit = build_mutation_error_audit(
        log,
        target_record=1,
        current_epoch=current_epoch,
        reason="replacement referenced a local that the plan never declared",
        recorded_at="2026-08-13T00:00:00+00:00",
    )
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(audit) + "\n")

    payload = summarize_experiments(
        tmp_path,
        current_epochs={log.parent.resolve(): current_epoch},
    )

    row = payload["rows"][0]
    assert payload["strict_errors"] == []
    assert row["current_errored_variants"] == 0
    assert row["audited_errored_variants"] == 1
    assert row["mutation_error_audits"] == 1
    assert row["current_inconclusive_sweeps"] == 1
    assert "audited-plan-errors" in row["flags"]
    assert "stalled" not in row["flags"]


def test_experiment_audit_command_appends_digest_bound_review(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratches" / "audited"
    scratch.mkdir(parents=True)
    log = scratch / "experiments.jsonl"
    current_epoch = "b" * 64
    failed = _result("failed", -1)
    failed["status"]["state"] = "error"
    _write_jsonl(
        log,
        [{"baseline_epoch": current_epoch, **_sweep("failed", [failed])}],
    )
    monkeypatch.setattr(
        "crimson.cli.match.matchlib.load_scratch_config",
        lambda directory: type("Config", (), {"directory": directory})(),
    )
    monkeypatch.setattr(
        "crimson.cli.match.matchlib.scratch_experiment_epoch",
        lambda config, match_root: current_epoch,
    )

    completed = CliRunner().invoke(
        match_app,
        [
            "experiment-audit",
            str(scratch),
            "--record",
            "1",
            "--reason",
            "replacement referenced an undeclared local",
            "--match-root",
            str(tmp_path),
            "--json",
        ],
    )

    assert completed.exit_code == 0
    appended = json.loads(completed.output)[0]
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert records[-1] == appended
    assert appended["kind"] == "mutation-error-audit"
    assert appended["target_record"] == 1
    assert appended["baseline_epoch"] == current_epoch
    assert appended["error_evidence_sha256"] == mutation_error_evidence_sha256(records[0])
