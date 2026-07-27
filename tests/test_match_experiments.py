from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match_experiments import summarize_experiments


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
        "evaluated_variants": len(results),
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
    path.parent.mkdir(parents=True)
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
        "kinds": {"mutation-sweep": 3, "probe": 1},
        "evaluated_variants": 4,
        "unique_variants": 3,
        "repeated_variants": 1,
        "improving_variants": 1,
        "neutral_variants": 2,
        "degrading_variants": 1,
        "tradeoff_variants": 1,
        "improving_sweeps": 1,
        "improving_probes": 1,
        "exact_winners": 1,
        "stalled_scratches": 0,
        "errors": 0,
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
    assert payload["summary"]["stalled_scratches"] == 1
    assert payload["summary"]["errors"] == 1
    assert payload["rows"][0]["flags"] == ["stalled", "malformed"]
