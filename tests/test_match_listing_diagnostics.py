from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path

import pytest

from crimson_re import match as matchlib
from crimson_re.match_listing_diagnostics import (
    compiler_stack_residual_payload,
    parse_stack_listing,
    render_stack_local_observations,
    stack_local_observations_payload,
)


def _result(target: tuple[str, ...], candidate: tuple[str, ...]) -> matchlib.MatchResult:
    return matchlib.MatchResult(
        ratio=difflib.SequenceMatcher(a=target, b=candidate, autojunk=False).ratio(),
        prefix_instructions=0,
        target_lines=target,
        candidate_lines=candidate,
        target_disassembly=tuple(matchlib.DisassemblyLine(i, 0x401000 + i, line, 1) for i, line in enumerate(target)),
        candidate_disassembly=tuple(matchlib.DisassemblyLine(i, i, line, 1) for i, line in enumerate(candidate)),
        body_byte_exact=False,
    )


def _listing(assembly: tuple[str, ...], declarations: str = "_local$ = -16") -> str:
    body = "\n".join(f"; {10 + i} : source\n  {i:05x}\t90\t {line}" for i, line in enumerate(assembly))
    return f"_TEXT\tSEGMENT\n{declarations}\n_foo PROC NEAR\n{body}\n_foo ENDP\n"


def test_stack_listing_scopes_aliases_and_wrapped_rows_to_selected_proc() -> None:
    text = (
        "_TEXT SEGMENT\n_wrong$ = -999\n_other PROC\n  00000\t90\t nop\n_other ENDP\n"
        "_TEXT SEGMENT\n_local$ = -16\n$T1 = -8\n_arg$ = 8\n_foo PROC NEAR\n"
        "; 10 : first source\n; 11 : second source\n  00000\tc7 44 24 14 00\n"
        "\t00 00 00\t mov DWORD PTR _local$[esp+36], 0\n"
        "  00008\td9 44 24 08\t fld DWORD PTR $T1[esp+16]\n_foo ENDP\n"
        "_TEXT SEGMENT\n_after PROC\n  00000\t90\t nop\n_after ENDP\n"
    )

    declarations, rows = parse_stack_listing(text, symbol="foo")

    assert declarations == {"_local$": -16, "$T1": -8, "_arg$": 8}
    assert list(rows) == [0, 8]
    assert rows[0].assembly == "mov DWORD PTR _local$[esp+36], 0"
    assert rows[0].source_lines == rows[8].source_lines == (10, 11)
    assert text.splitlines()[rows[0].listing_line - 1].startswith("\t00 00 00")


def test_stack_locals_keep_aliases_fields_and_unnamed_accesses_separate() -> None:
    result = _result(
        (
            "mov eax, dword [esp+0x14]",
            "mov ebx, dword [esp+0x18]",
            "mov ecx, dword [esp+0x10]",
            "mov edx, dword [esp+0x20]",
            "fld dword [esp+0x10]",
            "fstp dword [esp+0x18]",
            "fild dword [esp+0x20]",
            "mov edi, dword [ebp+0xc]",
        ),
        (
            "mov eax, dword [esp+0x10]",
            "mov ebx, dword [esp+0x14]",
            "mov ecx, dword [esp+0x10]",
            "mov edx, dword [esp+0x10]",
            "fld dword [esp+0x10]",
            "fstp dword [esp+0x10]",
            "fild dword [esp+0x10]",
            "mov edi, dword [ebp+0x8]",
        ),
    )
    text = _listing(
        (
            "mov eax, DWORD PTR _local$[esp+32]",
            "mov ebx, DWORD PTR _local$+4[esp+32]",
            "mov ecx, DWORD PTR _local$[esp+32]",
            "mov edx, DWORD PTR _alias$[esp+32]",
            "fld DWORD PTR $T1[esp+32]",
            "fstp DWORD PTR -16+[esp+32]",
            "fild DWORD PTR [esp+16]",
            "mov edi, DWORD PTR _arg$[ebp]",
        ),
        "_local$ = -16\n_alias$ = -16\n$T1 = -16\n_arg$ = 8",
    )

    payload = stack_local_observations_payload(result, text, symbol="foo")

    assert payload["summary"]["paired_stack_instructions"] == 8
    locals_by_name = {row["name"]: row for row in payload["locals"]}
    local = locals_by_name["_local$"]
    assert local["declared_frame_offset"] == -16
    assert local["conflicting_deltas"]
    assert {d["target_minus_candidate"]: d["observations"] for d in local["deltas"]} == {4: 2, 0: 1}
    assert local["deltas"][0]["sample"]["source_lines"] == [10]
    assert local["deltas"][0]["sample"]["target"]["address"] == 0x401000
    assert locals_by_name["_alias$"]["deltas"][0]["target_minus_candidate"] == 16
    assert locals_by_name["$T1"]["kind"] == "generated"
    assert locals_by_name["_arg$"]["declared_frame_offset"] == 8
    unnamed = payload["unnamed_frame_accesses"][0]
    assert unnamed["name"] is None
    assert unnamed["declared_frame_offset"] is None
    assert unnamed["listing_frame_offset"] == -16
    bare = payload["unannotated_accesses"][0]
    assert bare["name"] is None
    assert bare["listing_frame_offset"] is None
    assert bare["raw_candidate_displacement"] == 16
    assert "CONFLICTING DELTAS" in render_stack_local_observations(payload)
    assert "home=unknown" in render_stack_local_observations(payload)


@pytest.mark.parametrize(
    ("assembly", "reason"),
    [
        ("mov eax, DWORD PTR _local$[esp+36]", "listing-displacement-does-not-match-candidate"),
        ("mov eax, DWORD PTR _unknown$[esp+32]", "unknown or ambiguous compiler stack alias"),
    ],
)
def test_stack_locals_reject_inconsistent_listing_operands(assembly: str, reason: str) -> None:
    result = _result(("mov eax, dword [esp+0x14]",), ("mov eax, dword [esp+0x10]",))

    payload = stack_local_observations_payload(result, _listing((assembly,)), symbol="foo")

    assert not payload["locals"]
    assert payload["summary"]["skip_reasons"] == {reason: 1}


def test_stack_locals_preserve_repeated_uses_with_changing_esp_and_reused_aliases() -> None:
    result = _result(
        (
            "mov eax, dword [esp+0x14]",
            "push edx",
            "fld dword [esp+0x18]",
            "add esp, 0x4",
            "fstp dword [esp+0x1c]",
            "mov ebx, dword [esp+0x14]",
        ),
        (
            "mov eax, dword [esp+0x10]",
            "push edx",
            "fld dword [esp+0x14]",
            "add esp, 0x4",
            "fstp dword [esp+0x10]",
            "mov ebx, dword [esp+0x10]",
        ),
    )
    listing = _listing(
        (
            "mov eax, DWORD PTR _local$[esp+32]",
            "push edx",
            "fld DWORD PTR _local$[esp+36]",
            "add esp, 4",
            "fstp DWORD PTR _other$[esp+32]",
            "mov ebx, DWORD PTR _local$[esp+32]",
        ),
        "_local$ = -16\n_other$ = -16",
    )

    payload = stack_local_observations_payload(result, listing, symbol="foo")

    locals_by_name = {row["name"]: row for row in payload["locals"]}
    local = locals_by_name["_local$"]
    assert [sample["candidate"]["index"] for sample in local["accesses"]] == [0, 2, 5]
    assert [sample["listing_bias"] for sample in local["accesses"]] == [32, 36, 32]
    assert [sample["delta"] for sample in local["accesses"]] == [4, 4, 4]
    assert [sample["source_lines"] for sample in local["accesses"]] == [[10], [12], [15]]
    assert local["access_span"]["last"] == local["accesses"][-1]
    assert local["omitted_accesses"] == 0
    assert len(local["deltas"]) == 1
    assert locals_by_name["_other$"]["accesses"][0]["candidate"]["index"] == 4
    assert "not a live range" in payload["caveat"]
    assert "observed-use-span: native=0x00401000..0x00401005 candidate=+0x0..+0x5" in (
        render_stack_local_observations(payload)
    )


@pytest.mark.parametrize(
    "text",
    [
        "_foo PROC\n_foo ENDP\n_foo PROC\n_foo ENDP",
        "_local$ = -16\n_local$ = -8\n_foo PROC\n_foo ENDP",
    ],
)
def test_stack_listing_rejects_ambiguous_or_incomplete_scope(text: str) -> None:
    with pytest.raises(ValueError):
        parse_stack_listing(text, symbol="foo")


def _verified_listing(tmp_path: Path) -> tuple[matchlib.ScratchConfig, matchlib.CompilerListingResult]:
    cod = tmp_path / "foo.cod"
    cod.write_text(_listing(("mov eax, _local$[esp+32]",)))
    obj = tmp_path / "foo.obj"
    obj.write_bytes(b"verified object")
    sha = hashlib.sha256(obj.read_bytes()).hexdigest()
    metadata = tmp_path / "foo.json"
    metadata.write_text(
        json.dumps(
            {
                "object_function_equivalent": True,
                "listing_sha256": hashlib.sha256(cod.read_bytes()).hexdigest(),
                "canonical_object_sha256": sha,
            },
        ),
    )
    config = matchlib.ScratchConfig(
        directory=tmp_path,
        function="foo",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2",
        source="scratch.cpp",
        end_va=None,
        symbol="foo",
        note="",
    )
    listing = matchlib.CompilerListingResult(
        listing_path=cod,
        metadata_path=metadata,
        scratch=tmp_path,
        function="foo",
        compiler="msvc6.5",
        cflags="/O2",
        canonical_object=obj,
        canonical_object_sha256=sha,
        diagnostic_object_sha256=sha,
        function_sha256=hashlib.sha256(b"function").hexdigest(),
        function_bytes=8,
        relocations=0,
        spans=(),
        stack_layout=matchlib.CompilerListingStackLayout(None, ()),
    )
    return config, listing


@pytest.mark.parametrize("change", ["listing", "object"])
def test_compiler_stack_report_rejects_stale_provenance(tmp_path: Path, change: str) -> None:
    config, listing = _verified_listing(tmp_path)
    if change == "listing":
        listing.listing_path.write_text("stale listing")
    else:
        listing.canonical_object.write_bytes(b"changed object")

    with pytest.raises(ValueError, match="stale or inconsistent"):
        compiler_stack_residual_payload(config, listing)
