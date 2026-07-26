from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match import ScratchConfig, ScratchStatus
from crimson.match_mutation import (
    MutationEvaluation,
    MutationReplacement,
    MutationSite,
    MutationSpec,
    MutationSweep,
    MutationVariant,
    evaluate_mutation_sweep,
    generate_mutation_variants,
    load_mutation_spec,
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


def _status(config: ScratchConfig, ratio: float | None, *, prefix: int = 1) -> ScratchStatus:
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
    assert batch.truncated
    assert [variant.label for variant in batch.variants] == [
        "sum-order/commuted",
        "sum-order/parenthesized",
        "qualifier/const",
        "sum-order/commuted+qualifier/const",
    ]
    assert batch.variants[-1].source_text == "const int value = y + x;\n"


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
    ) -> ScratchStatus:
        del match_root
        ratio = 0.75 if "y + x" in source_text else 0.6
        return _status(replace(profile, directory=Path("/tmp/shadow")), ratio)

    monkeypatch.setattr("crimson.match_mutation.matchlib.evaluate_scratch", fake_baseline)
    monkeypatch.setattr("crimson.match_mutation.matchlib.evaluate_source_overlay", fake_overlay)

    sweep = evaluate_mutation_sweep(
        config,
        spec,
        source_text="int value = x + y;\n",
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


def test_mutate_cli_writes_only_an_improving_winner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = scratch / "scratch.cpp"
    source.write_text("int value = x + y;\n", encoding="utf-8")
    (scratch / "scratch.conf").write_text("FUNCTION=foo\n", encoding="utf-8")
    spec_path = tmp_path / "mutations.json"
    _write_spec(spec_path)
    config = _config(scratch)
    baseline = _status(config, 0.5)
    variant = MutationVariant(
        label="sum-order/commuted",
        source_text="int value = y + x;\n",
        source_sha256="variant",
        choices=(),
    )
    evaluation = MutationEvaluation(
        variant=variant,
        status=_status(replace(config, directory=Path("/tmp/shadow")), 0.75),
        baseline=baseline,
    )
    sweep = MutationSweep(
        spec=load_mutation_spec(spec_path),
        baseline=baseline,
        evaluations=(evaluation,),
        possible_variants=1,
        planned_variants=1,
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
            "--write-best",
            str(output),
            "--json",
        ],
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    assert payload["best_improves"] is True
    assert payload["best_source_written_to"] == str(output)
    assert output.read_text(encoding="utf-8") == variant.source_text
    assert source.read_text(encoding="utf-8") == "int value = x + y;\n"
