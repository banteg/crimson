"""Audit actual bytes and references of the stock highscore source witness."""

import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

from controls import HERE, WITNESS, build, sha, sources

from crimson import match

IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
NBASE = 0x4423D0
# Explicit native/candidate boundaries, verified against instruction boundaries below.
WINDOWS = {
    "row-and-buttons": (0x442B4D, 0x442F5C, 0x77D, 0xB8C),
    "filters": (0x4433C9, 0x443928, 0xFF5, 0x1554),
    "profile-label": (0x44340B, 0x44342D, 0x1037, 0x1059),
    "date-label": (0x4434F2, 0x443514, 0x111E, 0x1140),
}


def audit(body, native_rows, candidate_rows, window, image):
    ns, ne, cs, ce = window
    nr = [x for x in native_rows if ns <= x.address < ne]
    cr = [x for x in candidate_rows if cs <= x.offset < ce]
    assert len(nr) == len(cr) > 0
    assert nr[0].address == ns and nr[-1].address + nr[-1].size == ne
    assert cr[0].offset == cs and cr[-1].offset + cr[-1].size == ce
    assert ne - ns == ce - cs
    patched = bytearray(body.data[cs:ce])
    records, branches = [], []
    nbound = {x.address for x in native_rows}
    cbound = {x.offset for x in candidate_rows}
    for n, c in zip(nr, cr, strict=True):
        assert n.size == c.size and n.address - ns == c.offset - cs
        local = [r for r in body.relocation_references if c.offset <= r.offset < c.offset + c.size]
        assert len(local) == len(n.masked_references) == len(c.masked_references)
        for ref, native, candidate in zip(local, n.masked_references, c.masked_references, strict=True):
            assert native.explained and candidate.explained
            assert native.operand_index == candidate.operand_index and native.kind == candidate.kind
            # Require semantic address/name/content evidence, never a local-offset coincidence.
            shared = sorted(k for k in set(native.keys) & set(candidate.keys) if not k.startswith("local:"))
            assert shared and native.value is not None
            assert ref.relocation_type in (6, 20)
            assert cs <= ref.offset <= ce - 4
            address = native.value
            value = address if ref.relocation_type == 6 else (address - (ns + ref.offset - cs + 4)) & 0xFFFFFFFF
            struct.pack_into("<I", patched, ref.offset - cs, value)
            records.append({"offset": ref.offset, "address": address, "kind": ref.relocation_type, "shared": shared})
        if n.text.startswith("j"):
            nb = re.fullmatch(r"j\w+ L([0-9a-f]+)", n.text)
            cb = re.fullmatch(r"j\w+ L([0-9a-f]+)", c.text)
            assert nb and cb
            ndest, cdest = NBASE + int(nb[1], 16), int(cb[1], 16)
            assert ns <= ndest <= ne and cs <= cdest <= ce
            assert ndest in nbound and cdest in cbound
            assert ndest - ns == cdest - cs
            branches.append([n.address, ndest, c.offset, cdest])
    native_bytes = image.mapped[ns - image.image_base : ne - image.image_base]
    assert bytes(patched) == native_bytes
    return {
        "native_window": [ns, ne],
        "candidate_window": [cs, ce],
        "instructions": len(nr),
        "bytes": len(native_bytes),
        "relocations": records,
        "local_branches": branches,
        "stack_bindings": [],
        "resolved_bytes_sha256": sha(patched),
        "literal_branch_bytes_equal": True,
        "all_encoded_bytes_equal_after_reference_resolution": True,
        "full_function_match": False,
    }


def reject(label, fn):
    try:
        fn()
    except (AssertionError, ValueError):
        return label
    raise AssertionError(f"Accepted corruption: {label}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    image = match.load_image(match.default_image_path())
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    compiled = {}
    artifacts = {}
    for name in sources():
        cfg, _, body, r, measured = build(name, out / "controls")
        command = [
            sys.executable,
            str(HERE.parent / "highscore-residual-decomposition-2026-09-13/frame_map.py"),
            str(cfg.directory),
        ]
        frame = subprocess.run(command, cwd=match.REPO_ROOT, check=True, capture_output=True, text=True).stdout
        compiled[name] = {**measured, "frame_check": frame.strip().splitlines()}
        if name == WITNESS:
            artifacts[name] = (body, r)
        print("Verified stock build and frame", name, flush=True)
    body, r = artifacts[WITNESS]
    audits = {k: audit(body, r.target_disassembly, r.candidate_disassembly, w, image) for k, w in WINDOWS.items()}
    from dataclasses import replace

    bad = bytearray(body.data)
    bad[0x7CF] ^= 1  # Literal displacement of the empty-row exit.
    corruptions = [
        reject(
            "literal-row-branch",
            lambda: audit(
                replace(body, data=bytes(bad)),
                r.target_disassembly,
                r.candidate_disassembly,
                WINDOWS["row-and-buttons"],
                image,
            ),
        ),
    ]
    bad = bytearray(body.data)
    bad[0x103A] ^= 4  # Profile Y's actual ESP displacement; no binding is permitted.
    corruptions.append(
        reject(
            "label-stack-displacement",
            lambda: audit(
                replace(body, data=bytes(bad)),
                r.target_disassembly,
                r.candidate_disassembly,
                WINDOWS["profile-label"],
                image,
            ),
        ),
    )
    copied = list(r.candidate_disassembly)
    i = next(i for i, row in enumerate(copied) if row.offset == 0x103B)
    refs = list(copied[i].masked_references)
    refs[0] = replace(refs[0], keys=("name:wrong_constant",))
    copied[i] = replace(copied[i], masked_references=tuple(refs))
    corruptions.append(
        reject(
            "wrong-reference-owner", lambda: audit(body, r.target_disassembly, copied, WINDOWS["profile-label"], image),
        ),
    )
    removed = tuple(x for x in body.relocation_references if x.offset != 0x103D)
    assert len(removed) == len(body.relocation_references) - 1
    corruptions.append(
        reject(
            "omitted-relocation",
            lambda: audit(
                replace(body, relocation_references=removed),
                r.target_disassembly,
                r.candidate_disassembly,
                WINDOWS["profile-label"],
                image,
            ),
        ),
    )
    corruptions.append(
        reject(
            "truncated-window",
            lambda: audit(
                body, r.target_disassembly, r.candidate_disassembly, (0x44340B, 0x44342D, 0x1037, 0x1058), image,
            ),
        ),
    )
    # Identical normalized label instruction text must not hide different literals/strings.
    corruptions.append(
        reject(
            "date-substituted-for-profile",
            lambda: audit(
                body, r.target_disassembly, r.candidate_disassembly, (0x44340B, 0x44342D, 0x111E, 0x1140), image,
            ),
        ),
    )
    equal_pairs = [
        ("filter-copy-after-constructor-label-copy", "filter-copy-after-constructor-label-assign"),
        ("byte-full-version-label-copy", "byte-full-version-label-assign"),
        ("online-argument-snapshot", "float-before-constructor"),
    ]
    for a, b in equal_pairs:
        assert compiled[a]["normalized_coff_sha256"] == compiled[b]["normalized_coff_sha256"]
    result = {
        "schema": 1,
        "image_sha256": IMAGE_SHA,
        "witness": WITNESS,
        "scope": "stock-source-region-byte-proof-not-full-UI-execution",
        "compiled": compiled,
        "whole_coff_equal_pairs": equal_pairs,
        "audits": audits,
        "corruptions_rejected": corruptions,
        "input_hashes": {n: sha((HERE / n).read_bytes()) for n in ("controls.py", "controls.json", "verify.py")},
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified", len(audits), "native byte windows and", len(corruptions), "rejecting controls", flush=True)


if __name__ == "__main__":
    main()
