"""The online leaderboard's client side: the player's key, signed run uploads and the site login."""

from __future__ import annotations

from .client import Leaderboard, LeaderboardError
from .identity import Identity, IdentityError

__all__ = ["Identity", "IdentityError", "Leaderboard", "LeaderboardError"]
