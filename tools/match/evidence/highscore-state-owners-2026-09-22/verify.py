"""Verify every stock witness byte outside two explicit float-store residuals."""

import argparse
import json
import re
import struct
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from controls import HERE, WITNESS, build, sha, sources

from crimson import match

IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
NBASE = 0x4423D0
SIZE = 0x1F5A
EXCLUDED = ((0x1D8, 0x1E7), (0xF2F, 0xF4E))
WINDOWS = ((0, 0x1D8), (0x1E7, 0xF2F), (0xF4E, SIZE))


def audit(body, report, image, windows=WINDOWS):
    assert len(body.data) == SIZE
    native, candidate = report.target_disassembly, report.candidate_disassembly
    assert len(native) == len(candidate) == 2004
    nb = {r.offset for r in native} | {SIZE}
    cb = {r.offset for r in candidate} | {SIZE}
    records = []
    for start, end in windows:
        nr = [r for r in native if start <= r.offset < end]
        cr = [r for r in candidate if start <= r.offset < end]
        assert nr[0].offset == cr[0].offset == start
        assert nr[-1].offset + nr[-1].size == cr[-1].offset + cr[-1].size == end
        patched = bytearray(body.data[start:end])
        refs, branches = [], []
        for n, c in zip(nr, cr, strict=True):
            assert n.offset == c.offset and n.size == c.size
            relocations = [r for r in body.relocation_references if c.offset <= r.offset < c.offset + c.size]
            assert len(relocations) == len(n.masked_references) == len(c.masked_references)
            for ref, a, b in zip(relocations, n.masked_references, c.masked_references, strict=True):
                assert a.explained and b.explained and a.value is not None
                assert (a.operand_index, a.kind) == (b.operand_index, b.kind)
                shared = sorted(k for k in set(a.keys) & set(b.keys) if not k.startswith("local:"))
                assert shared and ref.relocation_type in (6, 20)
                assert start <= ref.offset <= end - 4
                value = a.value if ref.relocation_type == 6 else (a.value - (NBASE + ref.offset + 4)) & 0xFFFFFFFF
                struct.pack_into("<I", patched, ref.offset - start, value)
                refs.append({"offset": ref.offset, "address": a.value, "kind": ref.relocation_type, "shared": shared})
            if n.text.startswith("j"):
                a = re.fullmatch(r"(j\w+) L([0-9a-f]+)", n.text)
                b = re.fullmatch(r"(j\w+) L([0-9a-f]+)", c.text)
                assert a and b and a[1] == b[1]
                nd, cd = int(a[2], 16), int(b[2], 16)
                assert nd == cd and nd in nb and cd in cb
                branches.append([n.offset, nd])
        native_bytes = image.mapped[NBASE + start - image.image_base : NBASE + end - image.image_base]
        assert bytes(patched) == native_bytes
        records.append(
            {
                "window": [start, end],
                "instructions": len(nr),
                "bytes": end - start,
                "resolved_bytes_sha256": sha(patched),
                "relocations": refs,
                "literal_branches": branches,
                "stack_bindings": [],
            },
        )
    return records


def reject(name, action):
    try:
        action()
    except (AssertionError, ValueError):
        return name
    raise AssertionError(f"Accepted corruption: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    image = match.load_image(match.default_image_path())
    builds = {}
    bodies = {}
    witness = None
    for name in sources():
        cfg, _, body, report, measured = build(name, out / "controls")
        frame = subprocess.run(
            [
                sys.executable,
                str(HERE.parent / "highscore-residual-decomposition-2026-09-13/frame_map.py"),
                str(cfg.directory),
            ],
            cwd=match.REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        builds[name] = {**measured, "frame_check": frame.strip().splitlines()}
        bodies[name] = body.data
        if name == WITNESS:
            witness = body, report
        print("Verified stock build and frame", name, flush=True)
    body, report = witness
    differences = {}
    for before, after, offsets in (
        ("overlay-mode-copies", "status-shared-sleep", [0x16AD]),
        ("status-shared-sleep", WITNESS, [0x1784, 0x17C4]),
    ):
        changed = [[i, a, b] for i, (a, b) in enumerate(zip(bodies[before], bodies[after], strict=True)) if a != b]
        assert [r[0] for r in changed] == offsets
        differences[f"{before}->{after}"] = changed
    proof = audit(body, report, image)
    assert sum(r["bytes"] for r in proof) == 7980
    assert sum(r["instructions"] for r in proof) == 1993
    corruptions = []
    for name, offset, mask in (
        ("saved-mode-reference-bytes", 0xD8F, 1),
        ("shared-sleep-branch-destination", 0x16AD, 1),
        ("stage-zero-register", 0x1784, 0x20),
        ("literal-stack-displacement", 0x1F1, 4),
    ):
        damaged = bytearray(body.data)
        damaged[offset] ^= mask
        if name == "saved-mode-reference-bytes":
            # Relocation patching intentionally replaces encoded placeholders;
            # corrupt semantic ownership instead of a covered placeholder.
            rows = list(report.candidate_disassembly)
            index = next(i for i, r in enumerate(rows) if r.offset == 0xD8E)
            rows[index] = replace(
                rows[index], masked_references=(replace(rows[index].masked_references[0], keys=("name:wrong",)),),
            )
            corruptions.append(
                reject(name, lambda rows=rows: audit(body, replace(report, candidate_disassembly=tuple(rows)), image)),
            )
        else:
            corruptions.append(reject(name, lambda damaged=damaged: audit(replace(body, data=bytes(damaged)), report, image)))
    corruptions.append(reject("claim-entire-function", lambda: audit(body, report, image, ((0, SIZE),))))
    result = {
        "schema_version": 1,
        "kind": "highscore-state-owner-regions",
        "image_sha256": IMAGE_SHA,
        "witness": WITNESS,
        "source_sha256": sources()[WITNESS][1]["source_sha256"],
        "builds": builds,
        "proof": proof,
        "excluded_windows": EXCLUDED,
        "controlled_body_changes": differences,
        "proved_bytes": 7980,
        "proved_instructions": 1993,
        "full_function_match": False,
        "corruptions_rejected": corruptions,
        "inputs": {p.name: sha(p.read_bytes()) for p in (HERE / "controls.py", HERE / "controls.json", Path(__file__))},
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified 7980 bytes; two residual windows remain", flush=True)


if __name__ == "__main__":
    main()
