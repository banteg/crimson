from __future__ import annotations

from typing import Never


class WorldRendererMixinBase:
    """Allow cross-mixin attribute access without duplicating giant protocols."""

    def __getattr__(self, name: str) -> Never:
        raise AttributeError(name)
