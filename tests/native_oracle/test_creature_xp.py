"""Kill XP arithmetic vs the native `__ftol` award blocks.

- `creature_handle_death` 0x0041eb34..0x0041eb6e: Bloody Mess/Quick Learner
  `experience += __ftol(reward * 1.3f)`, otherwise
  `experience = __ftol((float)experience + reward)`.
- `creature_update_all` 0x0042704b..0x00427062: the Radioactive kill's
  `experience = __ftol((float)experience + reward)`.
- `perks_update_effects` 0x004070a6..0x004070cf: the Jinxed kill's
  `experience = __ftol((float)experience + reward)`.

`fild` loads the experience exactly, so the cases include totals past 2^24.
"""

from __future__ import annotations

import random

import pytest

from crimson.creatures.runtime import experience_plus_reward, quick_learner_kill_xp
from crimson.math_parity import f32

from ._support import CREATURE_LAYOUT, Mismatch, mismatch_report

_HANDLE_DEATH_XP_START = 0x0041EB34
_HANDLE_DEATH_XP_END = 0x0041EB6E
_RADIOACTIVE_XP_START = 0x0042704B
_RADIOACTIVE_XP_END = 0x00427062
_JINXED_XP_START = 0x004070A6
_JINXED_XP_END = 0x004070CF
_PERK_SLOT = 7


def _cases() -> list[tuple[int, float]]:
    rng = random.Random(0x41EB48)
    rewards = [90.0, 117.0, 433.0, 4500.0, 6600.0, f32(0.6666667 * 150.0)]
    rewards += [f32(rng.uniform(0.0, 5000.0)) for _ in range(200)]
    experiences = [0, 100, 12345, (1 << 24) - 3, (1 << 24) + 1, 20_000_001]
    return [(rng.choice(experiences), reward) for reward in rewards for _ in range(2)]


def test_handle_death_xp_matches_native(oracle) -> None:
    creature = oracle.alloc(0x98)
    oracle.write_u32("perk_id_bloody_mess_quick_learner", _PERK_SLOT)
    perk_count = oracle.resolve("player_perk_counts") + 4 * _PERK_SLOT
    reward_offset = CREATURE_LAYOUT["reward_value"][0]
    mismatches: list[Mismatch] = []
    cases = _cases()
    for experience, reward in cases:
        oracle.write_f32(creature + reward_offset, reward)
        for quick_learner in (True, False):
            oracle.write_u32(perk_count, int(quick_learner))
            oracle.write_u32("player_experience", experience)
            oracle.run(_HANDLE_DEATH_XP_START, _HANDLE_DEATH_XP_END, regs={"ebx": creature})
            native = oracle.read_i32("player_experience")
            python = (
                experience + quick_learner_kill_xp(reward)
                if quick_learner
                else experience_plus_reward(experience, reward)
            )
            if native != python:
                case = f"experience={experience} reward={reward!r} quick_learner={quick_learner}"
                mismatches.append(Mismatch(case, "experience", native, python, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=2 * len(cases))


@pytest.mark.parametrize(
    ("start", "end"),
    [(_RADIOACTIVE_XP_START, _RADIOACTIVE_XP_END), (_JINXED_XP_START, _JINXED_XP_END)],
    ids=["radioactive", "jinxed"],
)
def test_kill_xp_blocks_match_native(oracle, start: int, end: int) -> None:
    pool = oracle.resolve("creature_pool")
    reward_offset = CREATURE_LAYOUT["reward_value"][0]
    mismatches: list[Mismatch] = []
    cases = _cases()
    for experience, reward in cases:
        oracle.write_f32(pool + reward_offset, reward)
        oracle.write_u32("player_experience", experience)
        # esi indexes creature slot 0 (radioactive scales it by 8, Jinxed by 1).
        oracle.run(start, end, regs={"esi": 0})
        native = oracle.read_i32("player_experience")
        python = experience_plus_reward(experience, reward)
        if native != python:
            mismatches.append(Mismatch(f"experience={experience} reward={reward!r}", "experience", native, python, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=len(cases))
