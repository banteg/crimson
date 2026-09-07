from __future__ import annotations

import difflib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match import (
    DisassemblyLine,
    MaskedOperandAudit,
    MaskedOperandAuditEntry,
    MatchResult,
    ScratchConfig,
    match_result_payload,
)
from crimson.match_diagnostics import render_residual_summary, residual_summary_payload


def _result(
    target: tuple[str, ...],
    candidate: tuple[str, ...],
    *,
    target_offsets: tuple[int, ...] | None = None,
    candidate_offsets: tuple[int, ...] | None = None,
) -> MatchResult:
    target_offsets = target_offsets if target_offsets is not None else tuple(range(len(target)))
    candidate_offsets = candidate_offsets if candidate_offsets is not None else tuple(range(len(candidate)))
    return MatchResult(
        ratio=difflib.SequenceMatcher(a=target, b=candidate, autojunk=False).ratio(),
        prefix_instructions=next(
            (i for i, pair in enumerate(zip(target, candidate)) if pair[0] != pair[1]),
            min(len(target), len(candidate)),
        ),
        target_lines=target,
        candidate_lines=candidate,
        target_disassembly=tuple(
            DisassemblyLine(offset, 0x401000 + offset, line, 1)
            for offset, line in zip(target_offsets, target, strict=True)
        ),
        candidate_disassembly=tuple(
            DisassemblyLine(offset, offset, line, 1) for offset, line in zip(candidate_offsets, candidate, strict=True)
        ),
        body_byte_exact=False,
    )


def _branch_result(candidate_branch: str = "jne Le") -> MatchResult:
    return _result(
        ("push ebp", "mov eax, dword [esp+0x10]", "jne Lb", "xor ecx, ecx", "inc ebx", "nop", "ret"),
        ("push ebp", "mov eax, dword [esp+0x14]", candidate_branch, "xor ecx, ecx", "inc ebx", "nop", "ret"),
        target_offsets=(0, 1, 5, 7, 9, 10, 11),
        candidate_offsets=(0, 1, 8, 10, 12, 13, 14),
    )


def test_residual_summary_groups_displacements_without_changing_match_evidence() -> None:
    result = _branch_result()
    before = match_result_payload(result)

    payload = residual_summary_payload(result)

    assert payload["summary"]["branch_offset_pairs"] == 1
    assert payload["summary"]["stack_displacement_pairs"] == 1
    assert payload["summary"]["remaining_spans"] == 0
    assert payload["summary"]["identical_pairs"] == 5
    mapping = payload["stack_relationships"][0]
    assert (mapping["target"], mapping["candidate"], mapping["mapping"]) == (
        "[esp+0x10]",
        "[esp+0x14]",
        "one-to-one",
    )
    assert mapping["samples"][0]["target"]["address"] == 0x401001
    assert match_result_payload(result) == before
    assert not result.exact
    assert result.body_byte_exact is False


@pytest.mark.parametrize("branch", ["jne Lc", "jne Lb"])
def test_residual_summary_keeps_wrong_or_unknown_branch_destinations(branch: str) -> None:
    payload = residual_summary_payload(_branch_result(branch))

    assert payload["summary"]["branch_offset_pairs"] == 0
    assert payload["remaining"][0]["kind"] == (
        "branch-destination-conflict" if branch == "jne Lc" else "branch-destination-unchecked"
    )
    assert payload["remaining"][0]["target"]["start"] == 2


def test_residual_summary_checks_same_label_destinations_after_insertion() -> None:
    result = _result(
        ("jne L2", "inc eax", "ret"),
        ("jne L2", "push ebx", "inc eax", "ret"),
    )

    payload = residual_summary_payload(result)

    assert "branch-destination-conflict" in [span["kind"] for span in payload["remaining"]]


def test_residual_summary_includes_identity_observations_in_mapping_conflicts() -> None:
    result = _result(
        ("mov eax, dword [esp+0x10]", "mov ebx, dword [esp+0x10]", "mov ecx, dword [esp+0x18]"),
        ("mov eax, dword [esp+0x10]", "mov ebx, dword [esp+0x14]", "mov ecx, dword [esp+0x14]"),
    )

    payload = residual_summary_payload(result)

    assert payload["summary"]["stack_displacement_pairs"] == 2
    rows = {(row["target"], row["candidate"]): row for row in payload["stack_relationships"]}
    assert rows["[esp+0x10]", "[esp+0x10]"]["mapping"] == "one-to-many"
    assert rows["[esp+0x10]", "[esp+0x14]"]["mapping"] == "many-to-many"
    assert rows["[esp+0x18]", "[esp+0x14]"]["mapping"] == "many-to-one"
    assert all(row["conflicting"] for row in rows.values())
    assert payload["summary"]["conflicting_stack_relationships"] == 3


def test_residual_summary_flags_duplicate_alignment_evidence() -> None:
    result = _result(
        ("push eax", "mov eax, dword [esp+0x4]", "inc ecx", "mov eax, dword [esp+0x4]", "ret"),
        ("mov eax, dword [esp+0x8]", "xor ebx, ebx"),
    )

    payload = residual_summary_payload(result)

    assert payload["summary"]["ambiguous_pairs"] == 1
    assert payload["stack_relationships"][0]["ambiguous_observations"] == 1


def test_residual_summary_does_not_group_branch_with_ambiguous_destination() -> None:
    result = _result(
        ("jne L3", "push ebx", "ret", "ret"),
        ("jne L2", "pop ebx", "ret"),
    )

    payload = residual_summary_payload(result)

    assert payload["summary"]["branch_offset_pairs"] == 0
    assert "branch-destination-unchecked" in [span["kind"] for span in payload["remaining"]]


@pytest.mark.parametrize(
    ("target", "candidate"),
    [
        ("mov eax, dword [esp+ecx*4+0x10]", "mov eax, dword [esp+ecx*4+0x14]"),
        ("mov eax, dword [eax+0x10]", "mov eax, dword [eax+0x14]"),
        ("sub esp, 0x34", "sub esp, 0x38"),
        ("mov eax, dword [esp+0x10]", "mov ebx, dword [esp+0x14]"),
        ("mov eax, dword [esp+0x10]", "mov eax, word [esp+0x14]"),
        ("mov eax, dword [esp+0x10]", "mov eax, dword [ebp+0x14]"),
        ("je L2", "jne L2"),
    ],
)
def test_residual_summary_preserves_other_operands(target: str, candidate: str) -> None:
    payload = residual_summary_payload(_result((target,), (candidate,)))

    assert payload["summary"]["stack_displacement_pairs"] == 0
    assert payload["summary"]["branch_offset_pairs"] == 0
    assert payload["summary"]["remaining_target_instructions"] == 1
    assert payload["summary"]["remaining_candidate_instructions"] == 1


@pytest.mark.parametrize("negative", ["[ebp+-0x4]", "[ebp-0x4]"])
def test_residual_summary_accepts_signed_normalized_stack_operands(negative: str) -> None:
    payload = residual_summary_payload(_result((f"fld dword {negative}",), ("fld dword [ebp+-0x8]",)))

    assert payload["summary"]["stack_displacement_pairs"] == 1


def test_residual_summary_bounds_unaligned_output_and_handles_missing_addresses() -> None:
    result = _result(tuple(f"push 0x{i:x}" for i in range(100)), tuple(f"pop r{i}" for i in range(100)))
    result = replace(result, target_disassembly=(), candidate_disassembly=())

    payload = residual_summary_payload(result, context=1, limit=1)

    assert payload["summary"]["remaining_target_instructions"] == 100
    span = payload["remaining"][0]
    assert len(span["target"]["lines"]) == 14
    assert span["target"]["omitted_lines"] == 86
    assert span["target"]["lines"][0]["address"] is None
    assert "86 instructions omitted" in render_residual_summary(payload)
    assert "address unavailable" in render_residual_summary(payload)


def test_residual_summary_bounds_relationships_and_residuals_without_losing_totals() -> None:
    result = _result(
        ("mov eax, dword [esp+0x10]", "inc eax", "mov ebx, dword [esp+0x20]", "inc ebx"),
        ("mov eax, dword [esp+0x14]", "dec eax", "mov ebx, dword [esp+0x24]", "dec ebx"),
    )

    payload = residual_summary_payload(result, context=0, limit=1)

    assert len(payload["remaining"]) == len(payload["stack_relationships"]) == 1
    assert payload["summary"]["remaining_spans"] == payload["summary"]["stack_relationships"] == 2
    assert payload["omitted_remaining_spans"] == payload["omitted_stack_relationships"] == 1


@pytest.mark.parametrize("args", [[], ["--full"], ["--json"]])
def test_residual_summary_cli_preserves_failure_and_is_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
) -> None:
    result = _branch_result()
    monkeypatch.setattr("crimson.cli.match.matchlib.run_match", lambda **kwargs: result)
    runner = CliRunner()

    plain = runner.invoke(match_app, ["diff", "candidate.obj", "foo", *args])
    summary = runner.invoke(match_app, ["diff", "candidate.obj", "foo", "--residual-summary", *args])

    assert plain.exit_code == summary.exit_code == 1
    if "--json" in args:
        default_payload = json.loads(plain.output)
        summary_payload = json.loads(summary.output)
        assert "residual_summary" not in default_payload
        assert summary_payload.pop("residual_summary")["summary"]["branch_offset_pairs"] == 1
        assert summary_payload == default_payload
    else:
        assert "residual summary" not in plain.output
        assert "residual summary" in summary.output
        assert "--- target" in plain.output
        assert ("--- target" in summary.output) == ("--full" in args)
        assert "body_byte_exact=False" in summary.output


@pytest.mark.parametrize("as_json", [False, True])
def test_residual_summary_cannot_hide_reference_debt(monkeypatch: pytest.MonkeyPatch, as_json: bool) -> None:
    result = _result(("push ADDR",), ("push ADDR",))
    audit = MaskedOperandAudit((MaskedOperandAuditEntry(0, 0, 0, 0, 0x401000, 0, "push ADDR", (), (), "unresolved"),))
    result = replace(result, masked_operand_audit=audit)
    monkeypatch.setattr("crimson.cli.match.matchlib.run_match", lambda **kwargs: result)

    completed = CliRunner().invoke(
        match_app,
        ["diff", "candidate.obj", "foo", "--residual-summary", *(["--json"] if as_json else [])],
    )

    assert completed.exit_code == 1
    if as_json:
        payload = json.loads(completed.output)
        assert not payload["exact"]
        assert payload["references"]["unresolved"] == 1
        assert payload["residual_summary"]["summary"]["reference_problems"] == 1
    else:
        assert "refs=0/1/0" in completed.output
        assert "unresolved target=0x00401000" in completed.output


def test_residual_summary_scratch_cli_uses_same_report(monkeypatch: pytest.MonkeyPatch) -> None:
    config = ScratchConfig(
        directory=Path("scratch"),
        image="crimsonland.exe",
        function="foo",
        source="scratch.cpp",
        compiler="vc6",
        cflags="",
        end_va=None,
        symbol=None,
        note="",
    )
    monkeypatch.setattr("crimson.cli.match.matchlib.load_scratch_config", lambda path: config)
    monkeypatch.setattr("crimson.cli.match.matchlib.compile_scratch", lambda *args: Path("candidate.obj"))
    monkeypatch.setattr("crimson.cli.match.matchlib.run_match", lambda **kwargs: _branch_result())

    completed = CliRunner().invoke(match_app, ["scratch", "scratch", "--residual-summary"])

    assert completed.exit_code == 1
    assert "branch-offset-only=1" in completed.output


def test_residual_summary_bounds_reference_only_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _result(("push ADDR",) * 10, ("push ADDR",) * 10)
    audit = MaskedOperandAudit(tuple(
        MaskedOperandAuditEntry(i, i, i, i, 0x401000 + i, i, "push ADDR", (), (), "unresolved") for i in range(10)
    ))
    monkeypatch.setattr(
        "crimson.cli.match.matchlib.run_match", lambda **kwargs: replace(result, masked_operand_audit=audit),
    )

    completed = CliRunner().invoke(
        match_app, ["diff", "candidate.obj", "foo", "--residual-summary", "--max-regions", "1"],
    )

    assert completed.exit_code == 1
    assert completed.output.count("unresolved target=") == 1
    assert "9 more reference problems" in completed.output


def test_residual_summary_preserves_success_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _result(("ret",), ("ret",))
    monkeypatch.setattr("crimson.cli.match.matchlib.run_match", lambda **kwargs: result)

    completed = CliRunner().invoke(match_app, ["diff", "candidate.obj", "foo", "--residual-summary"])

    assert completed.exit_code == 0
    assert "remaining-insns=0/0" in completed.output
