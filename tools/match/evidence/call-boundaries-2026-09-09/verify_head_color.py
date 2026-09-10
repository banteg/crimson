"""Verify the fading-ion head's two color publications in native and compiled code.

This checks one straight-line call window, not full renderer equivalence.
"""

import argparse
import hashlib
import json
import re
from dataclasses import asdict, replace
from pathlib import Path

import capstone

from crimson import match

HERE = Path(__file__).resolve().parent
FUNCTION = "projectile_render"
COLOR_CALL = "call dword [REG+0x114]"
QUAD_CALL = "call dword [REG+0x11c]"
RGB_PUSHES = ["push 0x3f800000", "push 0x3f19999a", "push 0x3f000000"]
RESET = """            grim_interface_ptr->grim_set_color(
                0.5f, 0.6f, 1.0f, head_alpha);
"""
BOUNDARY = (
    """                32.0f,
                32.0f);
"""
    + RESET
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def call_kind(text):
    return re.sub(r"\b(eax|ecx|edx|ebp)\b", "REG", text)


def inspect_window(lines, data):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = {
        line.offset: next(decoder.disasm(data[line.offset : line.offset + line.size], line.address)) for line in lines
    }
    calls = [index for index, line in enumerate(lines) if line.text.startswith("call ")]
    windows = []
    for number in range(1, len(calls) - 2):
        selected = calls[number : number + 3]
        if [call_kind(lines[index].text) for index in selected] != [COLOR_CALL, QUAD_CALL, COLOR_CALL]:
            continue
        first, quad, last = selected
        preceding = lines[calls[number - 1] + 1 : first]
        first_pushes = [line for line in preceding if line.text.startswith("push ")][-4:]
        last_pushes = [line for line in lines[quad + 1 : last] if line.text.startswith("push ")]
        if len(first_pushes) != 4 or len(last_pushes) != 4:
            continue
        if [line.text for line in first_pushes[1:]] != RGB_PUSHES:
            continue
        if [line.text for line in last_pushes[1:]] != RGB_PUSHES:
            continue
        alpha = first_pushes[0].text.removeprefix("push ")
        if alpha not in {"ebx", "ebp", "esi", "edi"} or last_pushes[0].text != f"push {alpha}":
            continue
        start = next(i for i, line in enumerate(lines) if line.offset == first_pushes[0].offset)
        between = lines[start : last + 1]
        # Reject a merged branch's alternative argument pushes and any alternate
        # entry after the first call. The two publications must bracket this quad.
        if any(decoded[line.offset].group(capstone.CS_GRP_JUMP) for line in between):
            continue
        interior_start = lines[first].address + lines[first].size
        interior_end = lines[last].address + lines[last].size
        if any(
            instruction.group(capstone.CS_GRP_JUMP)
            and any(
                operand.type == capstone.x86.X86_OP_IMM and interior_start <= operand.imm < interior_end
                for operand in instruction.operands
            )
            for instruction in decoded.values()
        ):
            continue
        # x86 thiscall preserves these registers. Check all explicit writes in
        # the caller window; separately verify the shipped Grim implementations.
        if any(
            alpha in {instruction.reg_name(reg) for reg in instruction.regs_access()[1]}
            for line in between
            if not (instruction := decoded[line.offset]).group(capstone.CS_GRP_CALL)
        ):
            continue
        receiver_rows = []
        for previous, current in zip([calls[number - 1], first, quad], selected, strict=True):
            region = lines[previous + 1 : current]
            receivers = [line for line in region if line.text == "mov ecx, dword [ADDR]"]
            if not receivers:
                break
            receiver = receivers[-1]
            if not any(ref.explained and "address:0x0048083c" in ref.keys for ref in receiver.masked_references):
                break
            base = re.fullmatch(r"call dword \[(\w+)\+0x[0-9a-f]+\]", lines[current].text)[1]
            loads = [
                line for line in region if line.offset > receiver.offset and line.text == f"mov {base}, dword [ecx]"
            ]
            if not loads:
                break
            vtable = loads[-1]
            if any(
                base in {insn.reg_name(reg) for reg in insn.regs_access()[1]}
                for line in region
                if line.offset > vtable.offset and (insn := decoded[line.offset])
            ):
                break
            if any(
                "ecx" in {insn.reg_name(reg) for reg in insn.regs_access()[1]}
                for line in region
                if line.offset > receiver.offset and (insn := decoded[line.offset])
            ):
                break
            receiver_rows.append(
                {"load_offset": receiver.offset, "vtable_offset": vtable.offset, "global": "0x0048083c"},
            )
        if len(receiver_rows) != 3:
            continue
        quad_pushes = [line.text for line in lines[first + 1 : quad] if line.text.startswith("push ")]
        if len(quad_pushes) != 4 or quad_pushes[:2] != ["push 0x42000000"] * 2:
            continue
        windows.append(
            {
                "call_addresses": [lines[index].address for index in selected],
                "call_offsets": [lines[index].offset for index in selected],
                "alpha_register": alpha,
                "rgb_bits": ["3f000000", "3f19999a", "3f800000"],
                "quad_size_bits": ["42000000", "42000000"],
                "receivers": receiver_rows,
                "instructions": [{"offset": line.offset, "text": line.text} for line in between],
            },
        )
    assert len(windows) == 1, f"Expected one proved head-color window, found {len(windows)}"
    return windows[0]


def evaluate(config):
    obj_path = match.compile_scratch(config, force=True)
    obj = match.parse_coff_object(obj_path.read_bytes())
    body = match.extract_object_function(obj, config.symbol)
    result = match.run_match(
        obj_path=obj_path,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    return result, body.data, obj_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--source", type=Path, help="Validate a proposed projectile-render source")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    if args.source:
        directory = out / "source"
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_bytes(args.source.read_bytes())
        config = replace(config, directory=directory)
    source = (config.directory / config.source).read_text()
    assert source.count(BOUNDARY) == 1
    result, candidate, obj_path = evaluate(config)
    native_image = match.load_image(match.default_image_path())
    manifest = match.load_function_manifest(scope="all")
    _, start, end = match.resolve_function(manifest, FUNCTION)
    native = native_image.function_bytes(start, end)
    native_window = inspect_window(result.target_disassembly, native)
    assert native_window["call_addresses"] == [0x424AAE, 0x424AF3, 0x424B11]
    candidate_window = inspect_window(result.candidate_disassembly, candidate)
    negatives = []
    previous_problems = None
    for name, changed in {
        "removed-reset": source.replace(BOUNDARY, BOUNDARY.removesuffix(RESET), 1),
        "changed-reset-rgb": source.replace(BOUNDARY, BOUNDARY.replace("0.5f, 0.6f", "0.4f, 0.6f"), 1),
        "changed-reset-alpha": source.replace(
            BOUNDARY,
            BOUNDARY.replace("1.0f, head_alpha", "1.0f, head_alpha * 0.5f"),
            1,
        ),
    }.items():
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(changed)
        negative_result, negative_body, _ = evaluate(replace(config, directory=directory))
        if name == "removed-reset":
            previous_problems = [
                entry for entry in negative_result.masked_operand_audit.entries if entry.status != "ok"
            ]
        try:
            inspect_window(negative_result.candidate_disassembly, negative_body)
        except AssertionError:
            negatives.append({"name": name, "source_sha256": sha(changed.encode()), "rejected": True})
        else:
            raise AssertionError(f"Accepted the {name} negative control")
    problems = [entry for entry in result.masked_operand_audit.entries if entry.status != "ok"]
    assert previous_problems is not None

    def problem_identity(entry):
        return (
            entry.target_address,
            entry.status,
            tuple(ref.keys for ref in entry.target_references),
            tuple(ref.keys for ref in entry.candidate_references),
        )

    previous_identities = {problem_identity(entry) for entry in previous_problems}
    current_identities = {problem_identity(entry) for entry in problems}
    added = [entry for entry in problems if problem_identity(entry) not in previous_identities]
    removed = [entry for entry in previous_problems if problem_identity(entry) not in current_identities]
    receipt = {
        "schema": 1,
        "verified": True,
        "limitations": "One straight-line call window: same saved alpha bits and RGB constants before and after a 32px quad, "
        "with resolved receiver loads. Assumes x86 thiscall callee-saved registers. Does not prove head position, "
        "upstream alpha derivation, full renderer behavior, or whole-function exactness.",
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "source_sha256": sha(source.encode()),
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "candidate_body_sha256": sha(candidate),
        "candidate_object_sha256": sha(obj_path.read_bytes()),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "native": native_window,
        "candidate": candidate_window,
        "negative_controls": negatives,
        "reset_counterfactual_reference_audit": {
            "before_problems": len(previous_problems),
            "after_problems": len(problems),
            "previous_problem_identities_preserved": previous_identities <= current_identities,
            "added_pairings": [asdict(entry) for entry in added],
            "removed_pairings": [asdict(entry) for entry in removed],
        },
        "match": {
            "ratio": result.ratio,
            "instructions": [len(result.target_lines), len(result.candidate_lines)],
            "references": {
                "ok": result.masked_operand_audit.ok_count,
                "problems": result.masked_operand_audit.problem_count,
            },
            "exact": result.exact,
            "body_byte_exact": result.body_byte_exact,
        },
    }
    (out / "head-color.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Verified both head-color windows and rejected all three source defects")


if __name__ == "__main__":
    main()
