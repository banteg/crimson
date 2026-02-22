from __future__ import annotations

from .registry import all_views, view_by_name


def _register_builtin_views() -> None:
    from . import arsenal_debug as _arsenal_debug  # noqa: F401
    from . import beam_debug as _beam_debug  # noqa: F401
    from . import fonts as _fonts  # noqa: F401
    from . import game_over as _game_over  # noqa: F401
    from . import lighting_debug as _lighting_debug  # noqa: F401
    from . import perk_menu_debug as _perk_menu_debug  # noqa: F401
    from . import small_font_debug as _small_font_debug  # noqa: F401
    from . import spawn_plan as _spawn_plan  # noqa: F401


_register_builtin_views()

__all__ = ["all_views", "view_by_name"]
