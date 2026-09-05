from __future__ import annotations

from ...math_parity import f32
from ..runtime.apply_context import PerkApplyCtx


def apply_infernal_contract(ctx: PerkApplyCtx) -> None:
    ctx.owner.level += 3
    if ctx.perk_state is not None:
        ctx.perk_state.pending_count += 3
        ctx.perk_state.choices_dirty = True
    contract_players = ctx.players[:2] if ctx.state.preserve_bugs else ctx.players
    for player in contract_players:
        if player.health > 0.0:
            player.health = f32(0.1)
