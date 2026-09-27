from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from .raylib_api import rl

# raylib has no render target stack: EndTextureMode always returns to the window.
# Targets baked mid-frame (terrain) must hand drawing back to the enclosing target
# (the game canvas, the gamma pass) instead.
_stack: list[tuple[rl.RenderTexture, float, float]] = []


def _bind(target: rl.RenderTexture, scale_x: float, scale_y: float) -> None:
    rl.begin_texture_mode(target)
    # BeginTextureMode resets the modelview; scale logical coordinates into target pixels.
    rl.rl_scalef(scale_x, scale_y, 1.0)


@contextmanager
def texture_mode(target: rl.RenderTexture, *, scale_x: float = 1.0, scale_y: float = 1.0) -> Iterator[None]:
    _bind(target, scale_x, scale_y)
    _stack.append((target, scale_x, scale_y))
    try:
        yield
    finally:
        _stack.pop()
        if _stack:
            _bind(*_stack[-1])
        else:
            rl.end_texture_mode()
