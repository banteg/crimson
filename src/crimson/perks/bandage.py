from __future__ import annotations

from .apply_context import PerkApplyCtx


def apply_bandage(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            scale = float(ctx.state.rng.rand() % 50 + 1)
            player.health = min(100.0, player.health * scale)
            ctx.state.effects.spawn_burst(
                pos=player.pos,
                count=8,
                rand=ctx.state.rng.rand,
                detail_preset=5,
            )
