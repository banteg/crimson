from __future__ import annotations

from dataclasses import asdict

import pytest

from crimson import match as m
from crimson import match_address_diagnostics as address
from crimson import match_explain as explain


def reference(identity="address:0x0049bf4c", *, kind="disp", explained=True):
    return m.MaskedReference(0, kind, "test", None, identity, (identity,), explained)


def evidence(raw, refs):
    return {
        "instructions": [
            asdict(
                m.DisassemblyLine(
                    i.address,
                    i.address,
                    f"{i.mnemonic} {i.op_str}",
                    i.size,
                    (refs[i.address],) if i.address in refs else (),
                ),
            )
            for i in address.decode(raw).values()
        ],
    }


def test_coff_preserves_destination_register_and_reference_identity():
    left = bytes.fromhex("8b0d00000000c3")
    right = bytes.fromhex("8b1500000000c3")
    objects = [
        explain.coff(raw, "probe", [{"field_offset": 2, "symbol": "global", "type": 6}]) for raw in (left, right)
    ]
    for raw, obj in zip((left, right), objects, strict=True):
        extracted = m.extract_object_function(m.parse_coff_object(obj), "probe")
        assert extracted.data == raw
        assert extracted.relocation_offsets == frozenset({2})
    assert objects[0] != objects[1]
    assert explain.reference_key(reference(), "target") != explain.reference_key(
        reference("address:wrong"),
        "candidate",
    )
    assert explain.reference_key(reference(explained=False), "target") != explain.reference_key(
        reference(explained=False),
        "candidate",
    )


def test_wrapper_only_changes_independently_identified_reference_bytes():
    raw = bytes.fromhex("8b0d4cbf4900c3")
    ref = m.MaskedReference(1, "disp", "test", 0x49BF4C, "field", ("address:0x0049bf4c",), True)
    lines = tuple(m.DisassemblyLine(**i) for i in evidence(raw, {}).get("instructions", []))
    lines = (m.DisassemblyLine(0, 0, lines[0].text, 6, (ref,)), lines[1])
    obj, receipt = explain.wrapper(raw, lines, "target", "probe")
    assert m.extract_object_function(m.parse_coff_object(obj), "probe").data == bytes.fromhex("8b0d00000000c3")
    assert receipt["relocations"][0]["before"] == "4cbf4900"
    assert receipt["body_sha256"] == explain.digest(raw)


def test_reference_recheck_rejects_wrong_symbol_even_if_aligner_pairs_it():
    raw = bytes.fromhex("d90500000000c3")
    rows = explain.paired_rows(
        [(0, 0), (6, 6)],
        {
            "target": evidence(raw, {0: reference()}),
            "candidate": evidence(raw, {0: reference("address:wrong")}),
        },
    )
    assert rows[0]["reference_status"] == "mismatch"


@pytest.mark.parametrize("offsets", [[(0, 0)], [(0, 0), (0, 1)], [(1, 0), (0, 1)], [(0, 0), (2, 1)]])
def test_rejects_truncated_duplicate_reordered_and_foreign_offsets(offsets):
    item = evidence(bytes.fromhex("90c3"), {})
    with pytest.raises(ValueError, match="coverage"):
        explain.paired_rows(offsets, {"target": item, "candidate": item})


def test_retained_152_vs_19_times_eight_groups_related_operands():
    target = bytes.fromhex("e8000000008bf88d04ff8d3447c1e603d98600000000d98604000000c3")
    candidate = bytes.fromhex("e8000000008bf08d04f68d1c46d904dd00000000d904dd04000000c3")
    target_refs = {0: reference("name:find_creature", kind="imm"), 16: reference(), 22: reference("address:y")}
    candidate_refs = {0: reference("name:find_creature", kind="imm"), 13: reference(), 20: reference("address:y")}
    data = {"target": evidence(target, target_refs), "candidate": evidence(candidate, candidate_refs)}
    offsets = [(0, 0), (5, 5), (7, 7), (10, 10), (13, None), (16, 13), (22, 20), (28, 27)]
    groups = address.hypotheses(explain.paired_rows(offsets, data), {"target": target, "candidate": candidate})
    assert len(groups) == 1
    assert len(groups[0]["uses"]) == 2
    use = groups[0]["uses"][0]
    assert use["target"]["affine"] == use["candidate"]["affine"] == (152, 0)
    assert use["target"]["retained_registers"] == {"esi": (152, 0)}
    assert use["candidate"]["retained_registers"] == {"ebx": (19, 0)}


@pytest.mark.parametrize(
    ("body", "offset", "register", "expected"),
    [
        ("8bd8b30190", 9, "ebx", None),  # BL invalidates EBX.
        ("8bd8e80000000090", 12, "ebx", (1, 0)),  # ABI-preserved register.
        ("e80000000090", 10, "eax", None),  # Call destroys volatile EAX.
        ("8bd885c97403c1e30390", 14, "ebx", None),  # Join disagrees on scale.
        ("8bd885c97402909090", 13, "ebx", (1, 0)),  # Join agrees.
        ("8bd8c1e303ebfb", 7, "ebx", None),  # Loop cannot retain a changing affine value.
    ],
)
def test_must_analysis_kills_unproven_values(body, offset, register, expected):
    instructions = address.decode(bytes.fromhex("e800000000" + body + "c3"))
    states = address.trace_return(instructions, 0)
    assert states[offset].get(register) == expected


def test_relocated_lea_is_not_a_numeric_constant():
    instructions = address.decode(bytes.fromhex("e8000000008d980000000090c3"))
    assert address.trace_return(instructions, 0, frozenset({5}))[11].get("ebx") is None


@pytest.mark.parametrize(
    ("name", "left", "right", "symbols"),
    [
        ("self", "8b0d00000000c3", "8b0d00000000c3", ("global", "global")),
        ("relocated-register", "8b0d00000000c3", "8b1500000000c3", ("global", "global")),
        ("wrong-reference", "8b0d00000000c3", "8b0d00000000c3", ("global", "wrong")),
        ("esp-displacement", "8b442404c3", "8b442408c3", (None, None)),
        ("esi-displacement", "8b4604c3", "8b4608c3", (None, None)),
        (
            "branch-destination",
            "83f8007406b801000000c3b802000000c3",
            "83f8007405b801000000c3b802000000c3",
            (None, None),
        ),
        ("reordering", "b8010000008d4a04c3", "8d4a04b801000000c3", (None, None)),
    ],
)
def test_optional_real_engines(tmp_path, name, left, right, symbols):
    """Opt in with CRIMSON_TEST_{OBJDIFF,ASM_DIFFER,ASM_PYTHON,OBJDUMP}."""
    import json
    import os
    from pathlib import Path

    settings = {
        key: os.environ.get("CRIMSON_TEST_" + key.upper()) for key in ("objdiff", "asm_differ", "asm_python", "objdump")
    }
    if not all(settings.values()):
        pytest.skip("Optional external alignment tools not configured")
    for side, code, symbol in zip(("target", "candidate"), (left, right), symbols, strict=True):
        raw = bytes.fromhex(code)
        refs = (
            {} if symbol is None else {0: m.MaskedReference(1, "disp", "test", None, symbol, ("name:" + symbol,), True)}
        )
        data = evidence(raw, refs)
        lines = tuple(
            m.DisassemblyLine(
                i["offset"],
                i["address"],
                i["text"],
                i["size"],
                tuple(m.MaskedReference(**v) for v in i["masked_references"]),
            )
            for i in data["instructions"]
        )
        obj, receipt = explain.wrapper(raw, lines, side, "diagnostic_function")
        (tmp_path / f"{side}.obj").write_bytes(obj)
        explain.write_json(tmp_path / f"{side}-evidence.json", receipt)
    summary = explain.compare_bundle(
        tmp_path,
        engine="both",
        objdiff=str(settings["objdiff"]),
        asm_differ=Path(str(settings["asm_differ"])),
        asm_python=str(settings["asm_python"]),
        objdump=str(settings["objdump"]),
    )
    asm = json.loads((tmp_path / "levenshtein-raw.json").read_text())
    obj = json.loads((tmp_path / "objdiff-raw.json").read_text())
    changed = any(
        row.get("diff_kind", "DIFF_NONE") != "DIFF_NONE"
        for side in ("left", "right")
        for symbol in obj[side]["symbols"]
        for row in symbol.get("instructions", [])
    )
    assert (asm["current_score"] > 0) == changed == (name != "self")
    if name == "wrong-reference":
        assert all(counts["mismatch"] == 1 for counts in summary["reference_counts"].values())


def test_next_origin_call_ends_return_value_lifetime():
    # Second call returns a new value. Ending the first lifetime prevents an
    # unrelated next iteration from erasing the first one's retained index.
    raw = bytes.fromhex("e8000000008bd8e800000000ebf990c3")
    states = address.trace_return(address.decode(raw), 0, stop_calls=frozenset({7}))
    assert states[7]["ebx"] == (1, 0)
    assert 12 not in states


def test_loop_instruction_is_a_control_flow_edge():
    raw = bytes.fromhex("e8000000008bd8c1e303e2fb90c3")
    states = address.trace_return(address.decode(raw), 0)
    assert states[12].get("ebx") is None


def test_cli_refuses_existing_output_before_compiling(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from crimson.cli.match import match_app

    def unexpected_compile(*args, **kwargs):
        pytest.fail("Must not compile into an existing diagnostic bundle")

    monkeypatch.setattr(explain, "export_scratch", unexpected_compile)
    (tmp_path / "sentinel").write_text("preserve")
    result = CliRunner().invoke(match_app, ["explain", "scratch", "--out", str(tmp_path)])
    assert result.exit_code == 2
    assert "already exists" in result.output
    assert (tmp_path / "sentinel").read_text() == "preserve"
