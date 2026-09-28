from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from .raylib_api import rd, rl


@contextmanager
def blend_custom(src_factor: int, dst_factor: int, blend_equation: int) -> Iterator[None]:
    # NOTE: raylib/rlgl tracks custom blend factors as state; some backends only
    # apply them when switching the blend mode. Set factors both before and
    # after BeginBlendMode() to ensure the current draw uses the intended values.
    rl.rl_set_blend_factors(src_factor, dst_factor, blend_equation)
    rl.begin_blend_mode(rl.BlendMode.BLEND_CUSTOM)
    rl.rl_set_blend_factors(src_factor, dst_factor, blend_equation)
    try:
        yield
    finally:
        rl.end_blend_mode()


@contextmanager
def opaque_blend() -> Iterator[None]:
    """Overwrite the destination, ignoring source alpha.

    Render targets are RGBA, but translucent draws into them leave alpha below 1
    (rlgl blends the alpha channel with the color factors). The native D3D8 back
    buffer is XRGB, so presenting a finished target must not apply that alpha.
    """
    with blend_custom(rd.RL_ONE, rd.RL_ZERO, rd.RL_FUNC_ADD):
        yield
