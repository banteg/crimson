from __future__ import annotations

from .registry import all_views, view_by_name


def _register_builtin_views() -> None:
    from . import empty as _empty  # noqa: F401
    from . import fonts as _fonts  # noqa: F401
    from . import sprites as _sprites  # noqa: F401
    from . import terrain as _terrain  # noqa: F401


_register_builtin_views()

__all__ = ["all_views", "view_by_name"]
