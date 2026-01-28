from __future__ import annotations

from .registry import all_views, view_by_name


def _register_builtin_views() -> None:
    from . import empty as _empty  # noqa: F401
    from . import fonts as _fonts  # noqa: F401
    from . import animations as _animations  # noqa: F401
    from . import sprites as _sprites  # noqa: F401
    from . import terrain as _terrain  # noqa: F401
    from . import ground as _ground  # noqa: F401
    from . import projectiles as _projectiles  # noqa: F401
    from . import projectile_fx as _projectile_fx  # noqa: F401
    from . import bonuses as _bonuses  # noqa: F401
    from . import perks as _perks  # noqa: F401
    from . import perk_menu_debug as _perk_menu_debug  # noqa: F401
    from . import wicons as _wicons  # noqa: F401
    from . import ui as _ui  # noqa: F401
    from . import particles as _particles  # noqa: F401
    from . import spawn_plan as _spawn_plan  # noqa: F401
    from . import player as _player  # noqa: F401
    from . import survival as _survival  # noqa: F401
    from . import game_over as _game_over  # noqa: F401
    from . import small_font_debug as _small_font_debug  # noqa: F401
    from . import camera_debug as _camera_debug  # noqa: F401
    from . import camera_shake as _camera_shake  # noqa: F401
    from . import decals_debug as _decals_debug  # noqa: F401
    from . import corpse_stamp_debug as _corpse_stamp_debug  # noqa: F401
    from . import player_sprite_debug as _player_sprite_debug  # noqa: F401
    from . import aim_debug as _aim_debug  # noqa: F401
    from . import projectile_render_debug as _projectile_render_debug  # noqa: F401


_register_builtin_views()

__all__ = ["all_views", "view_by_name"]
