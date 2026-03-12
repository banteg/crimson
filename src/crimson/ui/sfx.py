from __future__ import annotations

from grim.rand import CallerStatic, CrandLike


def typeclick_sfx(rng: CrandLike, *, caller: CallerStatic = None) -> str:
    if (rng.rand(caller=caller) & 1) == 0:
        return "sfx_ui_typeclick_01"
    return "sfx_ui_typeclick_02"
