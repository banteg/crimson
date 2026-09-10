from __future__ import annotations

import difflib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match import DisassemblyLine, MaskedReference, MatchResult, ScratchConfig, match_result_payload
from crimson.match_flow_graph import flow_graph_payload


def result_for(target: tuple[str, ...], candidate: tuple[str, ...]) -> MatchResult:
    return MatchResult(
        ratio=difflib.SequenceMatcher(a=target, b=candidate, autojunk=False).ratio(),
        prefix_instructions=0,
        target_lines=target,
        candidate_lines=candidate,
        target_disassembly=tuple(DisassemblyLine(i, 0x401000 + i, line, 1) for i, line in enumerate(target)),
        candidate_disassembly=tuple(DisassemblyLine(i, i, line, 1) for i, line in enumerate(candidate)),
        body_byte_exact=False,
    )


def moved_blocks() -> MatchResult:
    return result_for(
        ("test eax, eax", "je L5", "mov eax, 0x1", "jmp L4", "ret", "mov eax, 0x2", "jmp L4"),
        ("test eax, eax", "je L4", "mov eax, 0x1", "ret", "mov eax, 0x2", "jmp L3"),
    )


def test_reordered_blocks_cover_operations_edges_and_transparent_jumps() -> None:
    result = moved_blocks()
    before = match_result_payload(result)
    graph = flow_graph_payload(result)
    assert graph["status"] == "matched"
    assert graph["mapped_non_jump_instructions"] == 5
    assert graph["transparent_jumps"] == [[3, 6], [5]]
    assert graph["all_instructions_covered"]
    assert [(row["target_index"], row["candidate_index"]) for row in graph["mapping"]] == [
        (0, 0), (1, 1), (2, 2), (4, 3), (5, 4),
    ]
    assert match_result_payload(result) == before
    assert not result.exact and not result.body_byte_exact


@pytest.mark.parametrize(("index", "text"), [(1, "jne L4"), (1, "je L2"), (2, "mov ebx, 0x1"), (2, "mov eax, 0x3")])
def test_changed_condition_destination_register_or_constant_fails(index: int, text: str) -> None:
    result = moved_blocks()
    candidate = list(result.candidate_lines)
    candidate[index] = text
    graph = flow_graph_payload(result_for(result.target_lines, tuple(candidate)))
    assert graph["status"] == "different"
    assert not graph["all_instructions_covered"]


def test_stack_operands_are_not_masked() -> None:
    graph = flow_graph_payload(result_for(
        ("mov eax, dword [esp+0x4]", "ret"), ("mov eax, dword [esp+0x8]", "ret"),
    ))
    assert graph["status"] == "different"


def test_distinct_return_nodes_cannot_collapse_into_one() -> None:
    graph = flow_graph_payload(result_for(("je L2", "ret", "ret"), ("je L1", "ret")))
    assert graph["status"] == "different"
    assert graph["failure"]["reason"] == "Candidate mapping is not one-to-one"


def test_one_return_node_cannot_expand_into_two() -> None:
    graph = flow_graph_payload(result_for(("je L1", "ret"), ("je L2", "ret", "ret")))
    assert graph["status"] == "different"
    assert graph["failure"]["reason"] == "Inconsistent target mapping"


@pytest.mark.parametrize("lines", [
    ("ret", "ret"),  # Unreachable operations cannot disappear from the accounting.
    ("jmp L0",),
    ("jmp L1", "jmp L0"),
    ("je Lf", "ret"),
    ("jmp eax",),
    ("jmp ADDR",),
    ("call L1", "ret"),
    ("call R+0x5", "ret"),
    ("push ADDR", "ret"),
    ("int3", "ret"),
    ("xbegin L1", "ret"),
    ("rep ret", "ret"),
    ("bnd jmp L1", "ret"),
    ("nop",),
    (),
])
def test_unsupported_or_incomplete_graphs_never_succeed(lines: tuple[str, ...]) -> None:
    graph = flow_graph_payload(result_for(lines, lines))
    assert graph["status"] == "unsupported"
    assert not graph["all_instructions_covered"]


@pytest.mark.parametrize("branch", ["jne", "loop", "jecxz"])
def test_conditional_cycles_are_checked(branch: str) -> None:
    graph = flow_graph_payload(result_for(("inc eax", f"{branch} L0", "ret"), ("inc eax", f"{branch} L0", "ret")))
    assert graph["status"] == "matched"
    assert graph["mapped_non_jump_instructions"] == 3


def test_repeated_string_operations_preserve_their_operands() -> None:
    lines = ("rep movsd dword es:[edi], dword [esi]", "ret")
    assert flow_graph_payload(result_for(lines, lines))["status"] == "matched"


def test_partial_masked_reference_evidence_is_unsupported() -> None:
    result = result_for(("mov dword [ADDR], ADDR", "ret"), ("mov dword [ADDR], ADDR", "ret"))
    ref = MaskedReference(0, "disp", "test", 0x401000, "owner", ("owner",), True)
    lines = (replace(result.target_disassembly[0], masked_references=(ref,)), result.target_disassembly[1])
    graph = flow_graph_payload(replace(result, target_disassembly=lines, candidate_disassembly=lines))
    assert graph["status"] == "unsupported"


@pytest.mark.parametrize("defect", ["absent", "text", "offset", "size", "entry"])
def test_inconsistent_decoded_evidence_is_unsupported(defect: str) -> None:
    result = result_for(("nop", "ret"), ("nop", "ret"))
    lines = result.candidate_disassembly
    if defect == "absent":
        lines = ()
    elif defect == "text":
        lines = (replace(lines[0], text="inc eax"), lines[1])
    elif defect == "offset":
        lines = (lines[0], replace(lines[1], offset=0))
    elif defect == "size":
        lines = (replace(lines[0], size=2), lines[1])
    else:
        lines = (replace(lines[0], offset=10), replace(lines[1], offset=11))
    assert flow_graph_payload(replace(result, candidate_disassembly=lines))["status"] == "unsupported"


@pytest.mark.parametrize("change", [None, "owner", "missing", "unexplained", "kind", "operand"])
def test_reference_evidence_checked_at_graph_mapped_positions(change: str | None) -> None:
    result = result_for(
        ("je L3", "nop", "ret", "push ADDR", "jmp L2"),
        ("je L4", "nop", "ret", "jmp L2", "push ADDR", "jmp L3"),
    )
    ref = MaskedReference(0, "imm", "test", 0x401000, "owner", ("owner",), True)
    left = list(result.target_disassembly)
    right = list(result.candidate_disassembly)
    left[3] = replace(left[3], masked_references=(ref,))
    altered = {
        None: (ref,), "owner": (replace(ref, keys=("wrong",)),), "missing": (),
        "unexplained": (replace(ref, explained=False),), "kind": (replace(ref, kind="disp"),),
        "operand": (replace(ref, operand_index=1),),
    }[change]
    right[4] = replace(right[4], masked_references=altered)
    graph = flow_graph_payload(replace(result, target_disassembly=tuple(left), candidate_disassembly=tuple(right)))
    if change is None:
        assert graph["status"] == "matched"
        assert graph["reference_instructions"] == 1
        assert graph["references"][0]["target_index"] == 3
        assert graph["references"][0]["candidate_index"] == 4
    else:
        assert graph["status"] != "matched"


@pytest.mark.parametrize("args", [[], ["--full"], ["--json"]])
def test_cli_adds_diagnostic_without_changing_failure_or_scores(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    monkeypatch.setattr("crimson.cli.match.matchlib.run_match", lambda **kwargs: moved_blocks())
    runner = CliRunner()
    plain = runner.invoke(match_app, ["diff", "candidate.obj", "foo", *args])
    graph = runner.invoke(match_app, ["diff", "candidate.obj", "foo", "--flow-graph", *args])
    assert plain.exit_code == graph.exit_code == 1
    if "--json" in args:
        payload = json.loads(graph.output)
        assert payload.pop("flow_graph")["status"] == "matched"
        assert payload == json.loads(plain.output)
    else:
        assert "flow graph: matched" in graph.output
        assert "flow graph:" not in plain.output
        assert ("--- target" in graph.output) == ("--full" in args)


def test_scratch_cli_exposes_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    config = ScratchConfig(Path("scratch"), "crimsonland.exe", "foo", "scratch.cpp", "vc6", "", None, None, "")
    monkeypatch.setattr("crimson.cli.match.matchlib.load_scratch_config", lambda path: config)
    monkeypatch.setattr("crimson.cli.match.matchlib.compile_scratch", lambda *args: Path("candidate.obj"))
    monkeypatch.setattr("crimson.cli.match.matchlib.run_match", lambda **kwargs: moved_blocks())
    completed = CliRunner().invoke(match_app, ["scratch", "scratch", "--flow-graph"])
    assert completed.exit_code == 1
    assert "flow graph: matched" in completed.output
