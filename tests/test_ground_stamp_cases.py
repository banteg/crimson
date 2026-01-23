from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "ground"
CASES_PATH = FIXTURE_DIR / "ground_stamp_cases.json"

CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011


def _generate_triplets(seed_state: int, stamps: int) -> list[list[int]]:
    state = seed_state & 0xFFFFFFFF
    out: list[list[int]] = []
    for _ in range(int(stamps)):
        state = (state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        rot = (state >> 16) & 0x7FFF
        state = (state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        ry = (state >> 16) & 0x7FFF
        state = (state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        rx = (state >> 16) & 0x7FFF
        out.append([int(rot), int(ry), int(rx)])
    return out


def test_ground_stamp_cases_match_captured_triplets() -> None:
    if not CASES_PATH.exists():
        pytest.skip(f"missing stamp fixtures: {CASES_PATH}")

    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    if not cases:
        pytest.skip("no stamp cases")

    failures: list[str] = []
    for case in cases:
        seed_state = int(case["seed_state"])
        expected = case["triplets_rot_y_x"]
        got = _generate_triplets(seed_state, len(expected))
        if got != expected:
            # Find the first mismatch for quick diagnosis.
            first = None
            for i, (a, b) in enumerate(zip(got, expected), start=1):
                if a != b:
                    first = (i, a, b)
                    break
            failures.append(
                f"stamp triplets mismatch for gen_index={case.get('gen_index')} seed_state=0x{seed_state:08x} "
                f"first_mismatch={first}"
            )

    if failures:
        pytest.fail("\n".join(failures))

