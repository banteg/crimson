from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match import ScratchConfig, ScratchStatus
from crimson.match_mutation import (
    MutationChoice,
    MutationEvaluation,
    MutationReplacement,
    MutationSite,
    MutationSpec,
    MutationSweep,
    MutationVariant,
    evaluate_mutation_sweep,
    generate_mutation_variants,
    load_mutation_spec,
    mutation_evaluation_payload,
    mutation_sweep_payload,
    render_mutation_sweep,
)


def _config(directory: Path) -> ScratchConfig:
    return ScratchConfig(
        directory=directory,
        function="foo",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="",
    )


def _status(
    config: ScratchConfig,
    ratio: float | None,
    *,
    prefix: int = 1,
    first_target_offset: int | None = 0x10,
    first_candidate_offset: int | None = 0x14,
) -> ScratchStatus:
    return ScratchStatus(
        config=config,
        address=0x401000,
        target_size=100,
        ratio=ratio,
        prefix_instructions=prefix,
        target_instructions=10,
        candidate_instructions=10,
        error="compile failed" if ratio is None else None,
        masked_ok=4,
        first_target_mismatch_offset=first_target_offset,
        first_candidate_mismatch_offset=first_candidate_offset,
    )


def _write_spec(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "sites": [
                    {
                        "name": "sum-order",
                        "find": "x + y",
                        "replacements": [
                            {"name": "commuted", "text": "y + x"},
                            {"name": "parenthesized", "text": "(x + y)"},
                        ],
                    },
                    {
                        "name": "qualifier",
                        "find": "int value",
                        "replacements": [{"name": "const", "text": "const int value"}],
                    },
                ],
            },
        ),
        encoding="utf-8",
    )


def test_mutation_spec_generates_bounded_combinations(tmp_path: Path) -> None:
    spec_path = tmp_path / "mutations.json"
    _write_spec(spec_path)
    spec = load_mutation_spec(spec_path)

    batch = generate_mutation_variants(
        "int value = x + y;\n",
        spec,
        max_changes=2,
        max_variants=4,
    )

    assert batch.possible_variants == 5
    assert batch.possible_by_changes == (3, 2)
    assert batch.planned_by_changes == (3, 1)
    assert batch.truncated
    assert [variant.label for variant in batch.variants] == [
        "sum-order/commuted",
        "sum-order/parenthesized",
        "qualifier/const",
        "sum-order/commuted+qualifier/const",
    ]
    assert batch.variants[-1].source_text == "const int value = y + x;\n"


def test_mutation_constraints_exclude_invalid_dependent_variants(tmp_path: Path) -> None:
    spec_path = tmp_path / "dependent.json"
    spec_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "sites": [
                    {
                        "name": "owner",
                        "find": "int value",
                        "replacements": [
                            {
                                "name": "declare-shared",
                                "text": "int shared; int value",
                                "conflicts": ["qualifier/make-const"],
                            },
                        ],
                    },
                    {
                        "name": "use",
                        "find": "return value",
                        "replacements": [
                            {
                                "name": "reuse-shared",
                                "text": "return shared",
                                "requires": ["owner/declare-shared"],
                            },
                        ],
                    },
                    {
                        "name": "qualifier",
                        "find": "value = 1",
                        "replacements": [
                            {"name": "make-const", "text": "value = 1 /* const shape */"},
                        ],
                    },
                ],
            },
        ),
        encoding="utf-8",
    )
    spec = load_mutation_spec(spec_path)

    batch = generate_mutation_variants(
        "int value; value = 1; return value;\n",
        spec,
        max_changes=2,
    )

    assert batch.possible_by_changes == (2, 1)
    assert [variant.label for variant in batch.variants] == [
        "owner/declare-shared",
        "qualifier/make-const",
        "owner/declare-shared+use/reuse-shared",
    ]
    assert not batch.truncated


def test_mutation_sites_reject_ambiguous_and_overlapping_spans() -> None:
    ambiguous = MutationSpec(
        sites=(
            MutationSite(
                name="sum",
                find="x",
                replacements=(MutationReplacement(name="y", text="y"),),
            ),
        ),
        sha256="spec",
    )
    with pytest.raises(ValueError, match="must match exactly once"):
        generate_mutation_variants("x + x", ambiguous)

    overlapping = MutationSpec(
        sites=(
            MutationSite(
                name="whole",
                find="x + y",
                replacements=(MutationReplacement(name="swap", text="y + x"),),
            ),
            MutationSite(
                name="left",
                find="x",
                replacements=(MutationReplacement(name="z", text="z"),),
            ),
        ),
        sha256="spec",
    )
    with pytest.raises(ValueError, match="overlap"):
        generate_mutation_variants("x + y", overlapping)


def test_mutation_sweep_evaluates_baseline_once_and_ranks_variants(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    config = _config(scratch)
    spec = MutationSpec(
        sites=(
            MutationSite(
                name="sum",
                find="x + y",
                replacements=(
                    MutationReplacement(name="commuted", text="y + x"),
                    MutationReplacement(name="parenthesized", text="(x + y)"),
                ),
            ),
        ),
        sha256="spec",
    )
    baseline_calls = 0

    def fake_baseline(profile: ScratchConfig, match_root: Path) -> ScratchStatus:
        nonlocal baseline_calls
        del match_root
        baseline_calls += 1
        return _status(profile, 0.5)

    def fake_overlay(
        profile: ScratchConfig,
        source_text: str,
        *,
        match_root: Path,
        source_path: Path | None,
    ) -> ScratchStatus:
        del match_root
        assert source_path == tmp_path / "shared.h"
        ratio = 0.75 if "y + x" in source_text else 0.6
        return _status(replace(profile, directory=Path("/tmp/shadow")), ratio)

    monkeypatch.setattr("crimson.match_mutation.matchlib.evaluate_scratch", fake_baseline)
    monkeypatch.setattr("crimson.match_mutation.matchlib.evaluate_source_overlay", fake_overlay)

    sweep = evaluate_mutation_sweep(
        config,
        spec,
        source_text="int value = x + y;\n",
        source_path=tmp_path / "shared.h",
        jobs=1,
        stop_on_improvement=True,
    )

    assert baseline_calls == 1
    assert len(sweep.evaluations) == 1
    assert sweep.stop_reason == "improvement"
    assert sweep.best_improves
    assert sweep.best is not None
    assert sweep.best.variant.label == "sum/commuted"
    assert sweep.best.fuzzy_delta_bytes == 25


def test_mutation_payload_warns_when_fuzzy_gain_regresses_other_metrics(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    baseline = _status(
        config,
        0.5,
        prefix=4,
        first_target_offset=0x20,
        first_candidate_offset=0x20,
    )
    candidate = replace(
        _status(
            replace(config, directory=Path("/tmp/shadow")),
            0.6,
            prefix=2,
            first_target_offset=0x10,
            first_candidate_offset=0x10,
        ),
        candidate_instructions=12,
        masked_ok=3,
        masked_mismatches=1,
    )
    variant = MutationVariant(
        label="shape/alternate",
        source_text="alternate",
        source_sha256="variant",
        choices=(
            MutationChoice(
                site="shape",
                replacement="alternate",
                replacement_index=1,
            ),
        ),
    )
    evaluation = MutationEvaluation(
        variant=variant,
        status=candidate,
        baseline=baseline,
    )
    sweep = MutationSweep(
        spec=MutationSpec(sites=(), sha256="spec"),
        baseline=baseline,
        evaluations=(evaluation,),
        possible_by_changes=(1,),
        planned_by_changes=(1,),
    )

    assert mutation_evaluation_payload(evaluation)["tradeoffs"] == [
        "reference-debt-increased",
        "resolved-references-decreased",
        "prefix-regressed",
        "first-mismatch-earlier",
        "instruction-count-further-from-target",
    ]
    payload = mutation_sweep_payload(sweep)
    assert payload["tradeoff_variants"] == 1
    assert payload["best_tradeoffs"] == mutation_evaluation_payload(evaluation)["tradeoffs"]
    assert payload["metric_best_improves"] is True
    assert payload["best_improves"] is False
    assert payload["winner"] is None


def test_mutation_payload_warns_when_fuzzy_tie_regresses_references(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    baseline = _status(config, 0.5)
    candidate = replace(
        _status(replace(config, directory=Path("/tmp/shadow")), 0.5),
        masked_ok=3,
        masked_mismatches=1,
    )
    evaluation = MutationEvaluation(
        variant=MutationVariant(
            label="bound/last-entry",
            source_text="last-entry",
            source_sha256="variant",
            choices=(
                MutationChoice(
                    site="bound",
                    replacement="last-entry",
                    replacement_index=1,
                ),
            ),
        ),
        status=candidate,
        baseline=baseline,
    )
    sweep = MutationSweep(
        spec=MutationSpec(sites=(), sha256="spec"),
        baseline=baseline,
        evaluations=(evaluation,),
        possible_by_changes=(1,),
        planned_by_changes=(1,),
    )

    expected = ["reference-debt-increased", "resolved-references-decreased"]
    assert mutation_evaluation_payload(evaluation)["tradeoffs"] == expected
    payload = mutation_sweep_payload(sweep)
    assert payload["tradeoff_variants"] == 1
    assert payload["best_tradeoffs"] == expected
    assert payload["metric_best_improves"] is False
    assert payload["best_improves"] is False
    assert payload["winner"] is None
    rendered = render_mutation_sweep(sweep)
    assert "tradeoffs=1" in rendered
    assert "[warn:reference-debt-increased,resolved-references-decreased]" in rendered


def test_mutate_cli_writes_only_a_tradeoff_free_improving_winner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = scratch / "scratch.cpp"
    source.write_text("int value = x + y;\n", encoding="utf-8")
    included_source = scratch / "shared_impl.h"
    included_source.write_text("int value = x + y;\n", encoding="utf-8")
    (scratch / "scratch.conf").write_text("FUNCTION=foo\n", encoding="utf-8")
    spec_path = tmp_path / "mutations.json"
    _write_spec(spec_path)
    config = _config(scratch)
    baseline = _status(config, 0.5)
    variant = MutationVariant(
        label="sum-order/commuted",
        source_text="int value = y + x;\n",
        source_sha256="variant",
        choices=(
            MutationChoice(
                site="sum-order",
                replacement="commuted",
                replacement_index=1,
            ),
        ),
    )
    evaluation_status = _status(
        replace(config, directory=Path("/tmp/shadow")),
        0.75,
        first_target_offset=0x18,
        first_candidate_offset=0x1C,
    )
    evaluation = MutationEvaluation(
        variant=variant,
        status=replace(evaluation_status, candidate_instructions=12),
        baseline=baseline,
    )
    second_variant = MutationVariant(
        label="qualifier/const",
        source_text="const int value = x + y;\n",
        source_sha256="second-variant",
        choices=(
            MutationChoice(
                site="qualifier",
                replacement="const",
                replacement_index=1,
            ),
        ),
    )
    second_evaluation = MutationEvaluation(
        variant=second_variant,
        status=_status(replace(config, directory=Path("/tmp/shadow-2")), 0.6),
        baseline=baseline,
    )
    sweep = MutationSweep(
        spec=load_mutation_spec(spec_path),
        baseline=baseline,
        evaluations=(evaluation, second_evaluation),
        possible_by_changes=(2, 3),
        planned_by_changes=(2, 0),
    )
    monkeypatch.setattr(
        "crimson.cli.match.match_mutation.evaluate_mutation_sweep",
        lambda *args, **kwargs: sweep,
    )
    output = tmp_path / "winner.cpp"

    completed = CliRunner().invoke(
        match_app,
        [
            "mutate",
            str(scratch),
            "--spec",
            str(spec_path),
            "--source",
            str(included_source),
            "--write-best",
            str(output),
            "--record",
            "--top",
            "1",
            "--json",
        ],
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    assert payload["best_improves"] is True
    assert payload["metric_best_improves"] is True
    assert payload["best_tradeoffs"] == ["instruction-count-further-from-target"]
    assert payload["best_source_written_to"] == str(output)
    assert payload["mutation_source"] == str(included_source)
    assert payload["recorded_to"] == str(scratch / "experiments.jsonl")
    assert payload["coverage_by_changes"][1] == {
        "changes": 2,
        "evaluated": 0,
        "never_evaluated": 3,
        "planned": 0,
        "possible": 3,
    }
    assert payload["combinations_never_evaluated"] == 3
    assert payload["results"][0]["delta"]["first_mismatch"]["probe_target_offset"] == 0x18
    assert len(payload["results"]) == 1
    assert output.read_text(encoding="utf-8") == second_variant.source_text
    assert source.read_text(encoding="utf-8") == "int value = x + y;\n"
    recorded = json.loads((scratch / "experiments.jsonl").read_text(encoding="utf-8"))
    assert recorded["kind"] == "mutation-sweep"
    assert len(recorded["baseline_epoch"]) == 64
    assert recorded["spec_sha256"] == sweep.spec.sha256
    assert recorded["winner"]["label"] == second_variant.label
    assert len(recorded["results"]) == 2
