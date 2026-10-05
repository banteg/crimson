from __future__ import annotations

import msgspec

from ..perks.availability import build_perk_availability
from ..quests.level import QUEST_COUNT
from ..sim.run_spec import RunSpec, RunStatus
from ..weapon_runtime.availability import build_weapon_availability


def unranked_reasons(run: RunSpec) -> list[str]:
    """Why a verified run falls outside the ranked profile; empty when it ranks.

    Effect detail and violence change which effect and blood draws the gameplay
    RNG makes, so ranked runs are played at full detail with violence on. They
    also start from a save with every quest unlock, so weapon and perk offers
    match. See docs/rewrite/parity/environment-rng.md.
    """

    reasons = []
    if run.detail_preset != 5:
        reasons.append("detail_preset")
    if run.violence_disabled:
        reasons.append("violence_disabled")
    if run.friendly_fire:
        reasons.append("friendly_fire")
    quest_count = QUEST_COUNT
    full = msgspec.structs.replace(
        run.status,
        quest_unlock_index=quest_count,
        quest_unlock_index_hardcore=quest_count,
    )
    if _unlocks(run.status, run) != _unlocks(full, run):
        reasons.append("unlocks")
    return reasons


def _unlocks(status: RunStatus, run: RunSpec) -> tuple[list[bool], list[bool]]:
    status_data = status.as_status_data()
    return (
        build_weapon_availability(status=status_data, game_mode=run.game_mode_id),
        build_perk_availability(status=status_data),
    )


__all__ = ["unranked_reasons"]
