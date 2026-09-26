"""Kill XP award in `creature_handle_death` (0x0041eb34..0x0041ebb5) vs `award_experience_from_reward`."""

from __future__ import annotations

import random

from crimson.gameplay import award_experience_from_reward
from crimson.math_parity import f32
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2

from ._support import Mismatch, mismatch_report


def test_kill_experience_award_matches_native(oracle) -> None:
    """`fild experience; fadd reward; __ftol`, repeated under Double Experience, including XP past 2^24."""

    creature = oracle.resolve("creature_pool")
    pristine = oracle.snapshot()
    rng = random.Random(0x41EB5B)
    mismatches: list[Mismatch] = []
    cases = 3000
    for _ in range(cases):
        experience = rng.choice((rng.randrange(0, 1 << 24), rng.randrange(1 << 24, 1 << 30)))
        reward = f32(rng.choice((rng.uniform(0.0, 400.0), float(rng.randrange(1, 400)))))
        double_experience = rng.choice((0.0, 5.0))

        oracle.restore(pristine)
        oracle.write_u32("player_experience", experience)
        oracle.write_f32(creature + 0x64, reward)
        oracle.write_f32("bonus_double_xp_timer", double_experience)
        oracle.run(0x0041EB34, 0x0041EBB5, regs={"ebx": creature})
        native = oracle.read_i32("player_experience")

        state = GameplayState()
        state.bonuses.double_experience = double_experience
        player = PlayerState(index=0, pos=Vec2(), experience=experience)
        award_experience_from_reward(state, player, reward)
        if player.experience != native:
            case = f"experience={experience} reward={reward!r} double={double_experience}"
            mismatches.append(Mismatch(case, "experience", native, player.experience, 0x0041EB5B))
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
