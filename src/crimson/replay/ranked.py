from __future__ import annotations

from pathlib import Path

import msgspec

from ..perks.availability import build_perk_availability
from ..persistence.save_status import GameStatus
from ..quests import all_quests
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
    quest_count = len(all_quests())
    full = msgspec.structs.replace(
        run.status,
        quest_unlock_index=quest_count,
        quest_unlock_index_full=quest_count,
    )
    if _unlocks(run.status, run) != _unlocks(full, run):
        reasons.append("unlocks")
    return reasons


def _unlocks(status: RunStatus, run: RunSpec) -> tuple[list[bool], list[bool]]:
    game_status = GameStatus.from_data(path=Path("run://status"), data=status.as_status_data(), dirty=False)
    return (
        build_weapon_availability(status=game_status, game_mode=run.game_mode_id),
        build_perk_availability(status=game_status),
    )


__all__ = ["unranked_reasons"]
