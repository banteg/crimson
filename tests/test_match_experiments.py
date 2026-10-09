from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from crimson_re.cli.match import match_app
from crimson_re.match_experiments import (
    build_mutation_error_audit,
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
