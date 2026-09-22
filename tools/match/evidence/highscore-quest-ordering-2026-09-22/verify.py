"""Audit the stock quest-arm witness, including all bytes and positional references."""

import argparse
import importlib.util
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from controls import HERE, WITNESS, build, sha, sources

from crimson import match

PREVIOUS = HERE.parent / "highscore-label-bitcopy-2026-09-22/verify.py"
spec = importlib.util.spec_from_file_location("label_region_audit", PREVIOUS)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
audit, reject, IMAGE_SHA = previous.audit, previous.reject, previous.IMAGE_SHA
WINDOWS = {
    "row-play-back": (0x442B4D, 0x4430EA, 0x77D, 0xD1A),
    "filter-core": (0x4433DC, 0x443928, 0x100B, 0x1557),
    "profile-label": (0x44340B, 0x44342D, 0x103A, 0x105C),
    "date-label": (0x4434F2, 0x443514, 0x1121, 0x1143),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    image = match.load_image(match.default_image_path())
    compiled = {}
    body = r = None
    for name in sources():
        cfg, _, current_body, current_result, measured = build(name, out / "controls")
        frame = subprocess.run(
            [
                sys.executable,
                str(HERE.parent / "highscore-residual-decomposition-2026-09-13/frame_map.py"),
                str(cfg.directory),
            ],
            cwd=match.REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        compiled[name] = dict(measured, frame_check=frame.stdout.strip().splitlines())
        if name == WITNESS:
            body, r = current_body, current_result
        print("Verified stock build and frame", name, flush=True)
    assert body is not None and r is not None
    audits = {k: audit(body, r.target_disassembly, r.candidate_disassembly, w, image) for k, w in WINDOWS.items()}
    rejected = []
    for label, offset, window in [
        ("wrong-hardcore-branch-polarity", 0xBBC, "row-play-back"),
        ("wrong-row-branch", 0x7CF, "row-play-back"),
        ("wrong-label-stack-displacement", 0x103D, "profile-label"),
    ]:
        bad = bytearray(body.data)
        bad[offset] ^= 1
        rejected.append(
            reject(
                label,
                lambda bad=bad, window=window: audit(
                    replace(body, data=bytes(bad)),
                    r.target_disassembly,
                    r.candidate_disassembly,
                    WINDOWS[window],
                    image,
                ),
            ),
        )
    copied = list(r.candidate_disassembly)
    i = next(i for i, row in enumerate(copied) if row.offset == 0xBB6)
    refs = list(copied[i].masked_references)
    refs[0] = replace(refs[0], keys=("name:quest_unlock_index",))
    copied[i] = replace(copied[i], masked_references=tuple(refs))
    rejected.append(
        reject(
            "wrong-hardcore-reference",
            lambda: audit(body, r.target_disassembly, copied, WINDOWS["row-play-back"], image),
        ),
    )
    removed = tuple(ref for ref in body.relocation_references if ref.offset != 0xBB8)
    assert len(removed) == len(body.relocation_references) - 1
    rejected.append(
        reject(
            "omitted-hardcore-relocation",
            lambda: audit(
                replace(body, relocation_references=removed),
                r.target_disassembly,
                r.candidate_disassembly,
                WINDOWS["row-play-back"],
                image,
            ),
        ),
    )
    rejected.append(
        reject(
            "date-substituted-for-profile",
            lambda: audit(
                body, r.target_disassembly, r.candidate_disassembly, (0x44340B, 0x44342D, 0x1121, 0x1143), image,
            ),
        ),
    )
    equal_pairs = [
        ("predicate", "quest-major-value"),
        ("predicate", "quest-parts-values"),
        ("quest-limit-reference", "quest-parts-references"),
    ]
    for a, b in equal_pairs:
        assert compiled[a]["normalized_coff_sha256"] == compiled[b]["normalized_coff_sha256"]
    result = {
        "schema": 1,
        "scope": "stock-source-region-proof-not-full-UI-execution",
        "witness": WITNESS,
        "image_sha256": IMAGE_SHA,
        "compiled": compiled,
        "audits": audits,
        "whole_coff_equal_pairs": equal_pairs,
        "corruptions_rejected": rejected,
        "input_hashes": {n: sha((HERE / n).read_bytes()) for n in ("controls.py", "controls.json", "verify.py")},
        "dependency_hashes": {str(PREVIOUS.relative_to(HERE.parent)): sha(PREVIOUS.read_bytes())},
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified", len(audits), "native byte windows and", len(rejected), "corruptions", flush=True)


if __name__ == "__main__":
    main()
