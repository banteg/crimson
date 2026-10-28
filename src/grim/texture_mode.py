from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from .edr import HDR_PIXEL_FORMAT, edr_headroom
from .raylib_api import rl

# raylib has no render target stack: EndTextureMode always returns to the window.
# Targets baked mid-frame (terrain) must hand drawing back to the enclosing target
# (the game canvas, the gamma pass) instead. Each entry: the target, its scale, and
# whether it holds linear light (the RTX world, linear_light.glsl).
_stack: list[tuple[rl.RenderTexture, float, float, bool]] = []


def _bind(target: rl.RenderTexture, scale_x: float, scale_y: float, _linear: bool = False) -> None:
    rl.begin_texture_mode(target)
    # BeginTextureMode resets the modelview; scale logical coordinates into target pixels.
    rl.rl_scalef(scale_x, scale_y, 1.0)


def current_target_size() -> tuple[int, int]:
    if _stack:
        target = _stack[-1][0]
        return int(target.texture.width), int(target.texture.height)
    return int(rl.get_render_width()), int(rl.get_render_height())


def current_target_scale() -> tuple[float, float]:
    """Target pixels per logical unit in the current target."""
    if _stack:
        return _stack[-1][1], _stack[-1][2]
    # The window: raylib scales logical coordinates into a HiDPI framebuffer itself.
    dpi = rl.get_window_scale_dpi()
    return float(dpi.x), float(dpi.y)


def current_target_edr_headroom() -> float:
    # Every enclosing compositing pass must preserve extended values.
    if any(int(target.texture.format) != int(HDR_PIXEL_FORMAT) for target, *_ in _stack):
        return 1.0
    return edr_headroom()


def current_target_linear() -> bool:
    """Whether draws land in linear light, where artwork's colors decode (linear_light.glsl's worldColor)."""
    return bool(_stack) and _stack[-1][3]


def restore_current_target() -> None:
    """Restore the enclosing projection/target after raw framebuffer operations.

    Float-target allocation can temporarily bind a different framebuffer, even
    when allocation fails. Call this in a finally block before resuming drawing.
    """
    if _stack:
        _bind(*_stack[-1])
    else:
        rl.end_texture_mode()


@contextmanager
def texture_mode(
    target: rl.RenderTexture, *, scale_x: float = 1.0, scale_y: float = 1.0, linear: bool = False,
) -> Generator[None]:
    _bind(target, scale_x, scale_y)
    _stack.append((target, scale_x, scale_y, linear))
    try:
        yield
    finally:
        _stack.pop()
        restore_current_target()
