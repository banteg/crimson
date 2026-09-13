"""Rebuild every retained source control and prove the full native function."""

import argparse
import json
import re
from dataclasses import replace
from pathlib import Path

from positions import inspect
from recover import HERE, recover, sha

from crimson import match

IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"


def metrics(result):
    return {
        "instructions": len(result.candidate_lines), "native_instructions": len(result.target_lines),
        "prefix": result.prefix_instructions, "exact": result.exact, "body_byte_exact": result.body_byte_exact,
        "refs": [result.masked_operand_audit.ok_count, result.masked_operand_audit.unresolved_count, result.masked_operand_audit.mismatch_count],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--final-only", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    graph = json.loads((HERE / "experiments.json").read_text())
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_spawn_template")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    rows = []
    names = [graph["final"]] if args.final_only else ["before", *graph["experiments"]]
    final = final_object = None
    for index, name in enumerate(names):
        directory = args.out / name
        directory.mkdir(exist_ok=True)
        source = recover(name)
        (directory / config.source).write_text(source)
        expected = graph["experiments"].get(name)
        cfg = replace(config, directory=directory, cflags=expected["cflags"] if expected else config.cflags)
        obj = match.compile_scratch(cfg, force=True)
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
        assert sha(body.data) == (expected["body_sha256"] if expected else graph["before_body_sha256"]), name
        result = match.run_match(obj_path=obj, function=cfg.function, symbol_name=cfg.symbol, reference_aliases=cfg.reference_aliases)
        actual = metrics(result)
        if expected:
            assert actual == {key: expected[key] for key in actual}, (name, actual)
        else:
            assert not result.exact and not result.body_byte_exact
        rows.append({"name": name, "source_sha256": sha(source.encode()), "body_sha256": sha(body.data), "metrics": actual})
        if name == graph["final"]:
            final, final_object = result, obj
            assert actual == {"instructions": 3159, "native_instructions": 3159, "prefix": 3159, "exact": True, "body_byte_exact": True, "refs": [363, 0, 0]}
            assert len(body.data) == sum(line.size for line in result.target_disassembly) == 14099
            assert result.target_padding_bytes == result.candidate_padding_bytes == 0
            assert not result.body_byte_mismatches
            assert result.target_disassembly[0].address == 0x430AF0
            assert result.target_disassembly[-1].address + result.target_disassembly[-1].size == 0x434203
            position = inspect(result.target_disassembly, result.candidate_disassembly)
        print(f"{index + 1}/{len(names)} {name} PASS", flush=True)
    assert final is not None and final_object is not None
    rejected = []
    for kind in ("branch", "reference", "stack", "retry-table"):
        lines = list(final.candidate_disassembly)
        if kind == "branch":
            i = next(i for i, line in enumerate(lines) if re.fullmatch(r"j\w+ L[0-9a-f]+", line.text))
            lines[i] = replace(lines[i], text=lines[i].text.split()[0] + " L0")
        elif kind in ("reference", "retry-table"):
            i = next(i for i, line in enumerate(lines) if line.text == "jmp dword [eax*4+ADDR]") if kind == "retry-table" else next(i for i, line in enumerate(lines) if line.masked_references)
            refs = list(lines[i].masked_references)
            keys = ("compiler:vc6-local-jump-table:0x0,0x360c,0x363e,0x366d",) if kind == "retry-table" else ("wrong-owner",)
            refs[0] = replace(refs[0], keys=keys)
            lines[i] = replace(lines[i], masked_references=tuple(refs))
        else:
            i = next(i for i, line in enumerate(lines) if "[esp+0x" in line.text)
            lines[i] = replace(lines[i], text=re.sub(r"\[esp\+0x([0-9a-f]+)\]", lambda m: f"[esp+0x{int(m[1], 16) + 4:x}]", lines[i].text))
        try:
            inspect(final.target_disassembly, lines)
        except AssertionError:
            rejected.append(kind)
        else:
            raise AssertionError("Accepted altered " + kind)
    directory = args.out / "changed-grid-stride"
    directory.mkdir(exist_ok=True)
    source = recover()
    assert source.count("ring_member_idx += 0x40") == 1
    (directory / config.source).write_text(source.replace("ring_member_idx += 0x40", "ring_member_idx += 0x10"))
    obj = match.compile_scratch(replace(config, directory=directory), force=True)
    wrong = match.run_match(obj_path=obj, function=config.function, symbol_name=config.symbol, reference_aliases=config.reference_aliases)
    assert not wrong.exact and not wrong.body_byte_exact
    compiler = match._compiler_executable_path(config, match.DEFAULT_MATCH_ROOT).parent
    receipt = {
        "schema_version": 1, "function": config.function, "image_sha256": IMAGE_SHA,
        "source_sha256": sha(source.encode()), "object_sha256": sha(final_object.read_bytes()),
        "compiler": config.compiler, "cflags": config.cflags, "reference_aliases": config.reference_aliases,
        "compiler_inputs_sha256": {name: sha((compiler / name).read_bytes()) for name in ("CL.EXE", "C1XX.DLL", "C2.DLL", "../Include/math.h")},
        "native_start": 0x430AF0, "native_end": 0x434203, "encoded_body_bytes": 14099,
        "final": metrics(final), "positions": position, "rows": rows,
        "changed_stride_rejected": metrics(wrong), "positional_controls_rejected": rejected,
        "harness_sha256": {path.name: sha(path.read_bytes()) for path in (HERE / "verify.py", HERE / "positions.py", HERE / "recover.py", HERE / "before.cpp", HERE / "experiments.json")},
        "scope": "Full function encoded-body, extent and positional reference proof. Compiler observations and finite execution coverage are separate evidence.",
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS exact creature_spawn_template", flush=True)


if __name__ == "__main__":
    main()
