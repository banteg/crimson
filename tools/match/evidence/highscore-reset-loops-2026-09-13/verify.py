"""Verify the five native signed pool-reset branches and whole-body locality."""

import argparse
import hashlib
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import capstone

from crimson import match

BASE = "89dcf708447b44d35cf4f791427a78e2f0ec877e"
SCRATCH = Path("tools/match/scratches/highscore_screen_update")
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
BRANCHES = (0xCFA, 0xD0C, 0xD1E, 0xD30, 0xD44)
NATIVE_WINDOW = (0xD2D, 0xD88)
CANDIDATE_WINDOW = (0xCEB, 0xD46)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=match.REPO_ROOT / SCRATCH / "scratch.cpp")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    cfg = match.load_scratch_config(match.REPO_ROOT / SCRATCH)
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to load the pinned baseline")
    sources = (
        subprocess.check_output([git, "show", f"{BASE}:{SCRATCH}/scratch.cpp"], cwd=match.REPO_ROOT),
        args.source.read_bytes(),
    )
    functions, results = [], []
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    for label, source in zip(("before", "after"), sources, strict=True):
        directory = args.out / label
        directory.mkdir(parents=True, exist_ok=True)
        (directory / cfg.source).write_bytes(source)
        obj = match.compile_scratch(replace(cfg, directory=directory), force=True)
        functions.append(match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol))
        results.append(
            match.run_match(
                obj_path=obj,
                function=cfg.function,
                symbol_name=cfg.symbol,
                reference_aliases=cfg.reference_aliases,
            ),
        )
    before, after = functions
    assert len(before.data) == len(after.data) == 7894
    changed = [i for i, (old, new) in enumerate(zip(before.data, after.data, strict=True)) if old != new]
    assert tuple(changed) == BRANCHES
    assert all((before.data[i], after.data[i]) == (0x72, 0x7C) for i in changed)
    assert before.relocation_references == after.relocation_references
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for function in functions:
        rows = list(decoder.disasm(function.data, 0))
        assert len(rows) == 1969 and sum(row.size for row in rows) == len(function.data)
        assert all(row.size == 2 for row in rows if row.address in BRANCHES)
    result = results[1]
    windows = [
        [row for row in rows if start <= row.offset < end]
        for rows, (start, end) in zip(
            (result.target_disassembly, result.candidate_disassembly),
            (NATIVE_WINDOW, CANDIDATE_WINDOW),
            strict=True,
        )
    ]
    assert all(len(rows) == 25 for rows in windows)
    for target, candidate in zip(*windows, strict=True):
        assert target.offset - NATIVE_WINDOW[0] == candidate.offset - CANDIDATE_WINDOW[0]
        if target.text.startswith("jl "):
            assert candidate.text.startswith("jl ")
            assert int(target.text[4:], 16) - NATIVE_WINDOW[0] == int(candidate.text[4:], 16) - CANDIDATE_WINDOW[0]
        else:
            assert target.text == candidate.text
    references = [
        entry
        for entry in result.masked_operand_audit.entries
        if NATIVE_WINDOW[0] <= entry.target_offset < NATIVE_WINDOW[1]
    ]
    assert len(references) == 10
    assert all(
        entry.status == "ok" and entry.target_offset - NATIVE_WINDOW[0] == entry.candidate_offset - CANDIDATE_WINDOW[0]
        for entry in references
    )
    assert all(not r.exact and not r.body_byte_exact for r in results)
    assert all(
        r.prefix_instructions == 45
        and r.masked_operand_audit.ok_count == 594
        and r.masked_operand_audit.problem_count == 4
        for r in results
    )
    payload = {
        "schema": 1,
        "kind": "highscore-reset-loop-locality",
        "base_commit": BASE,
        "image_sha256": IMAGE_SHA,
        "source_sha256": [sha(s) for s in sources],
        "body_sha256": [sha(f.data) for f in functions],
        "body_bytes": 7894,
        "candidate_instructions": 1969,
        "native_instructions": 2004,
        "changed_opcode_offsets": changed,
        "before_opcode": "jb",
        "after_opcode": "jl",
        "outside_bytes_unchanged": 7889,
        "all_relocations_unchanged": True,
        "native_window": NATIVE_WINDOW,
        "candidate_window": CANDIDATE_WINDOW,
        "window_instructions": 25,
        "window_positional_references": 10,
        "normalized_exact": False,
        "body_byte_exact": False,
        "verified": True,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
    }
    (args.out / "results.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
