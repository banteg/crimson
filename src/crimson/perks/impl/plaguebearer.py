from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx


def apply_plaguebearer(ctx: PerkApplyCtx) -> None:
    # Native sets only player zero's contact-infection flag. Keep the co-op fix
    # by default, but retain that asymmetry for parity captures.
    players = ctx.players[:1] if ctx.state.preserve_bugs else ctx.players
    for player in players:
        player.plaguebearer_active = True
