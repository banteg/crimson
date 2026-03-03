from __future__ import annotations

from .apply_context import BonusApplyCtx
from .payload import BonusPointsPayload, bonus_payload_from_bonus


def apply_points(ctx: BonusApplyCtx) -> None:
    # Native adds Points directly to player0 XP (no Double XP multiplier).
    payload = bonus_payload_from_bonus(
        bonus_id=ctx.bonus_id,
        amount=int(ctx.amount),
    )
    amount = int(payload.points) if isinstance(payload, BonusPointsPayload) else int(ctx.amount)
    if amount <= 0:
        return
    target = ctx.player
    if len(ctx.players) > 0:
        target = ctx.players[0]
    target.experience += int(amount)
