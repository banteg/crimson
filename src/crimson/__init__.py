from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("crimsonland")
except PackageNotFoundError:  # pragma: no cover
    # Allow running from source (e.g. `PYTHONPATH=src`) without installed package metadata.
    __version__ = "0.0.0+dev"

__all__ = [
    "atlas",
    "audio_router",
    "bonuses",
    "creatures",
    "gameplay",
    "effects",
    "effects_atlas",
    "modes",
    "perks",
    "persistence",
    "quests",
    "replay",
    "render",
    "sim",
    "ui",
    "views",
    "weapons",
]
