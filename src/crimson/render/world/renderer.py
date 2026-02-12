from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from grim.fonts.small import SmallFontData

from ..frame import RenderFrame
from .bonuses import WorldRendererBonusesMixin
from .context import WorldRendererContextMixin
from .creatures import WorldRendererCreaturesMixin
from .draw import WorldRendererDrawMixin
from .effects import WorldRendererEffectsMixin
from .overlays import WorldRendererOverlaysMixin
from .projectiles import WorldRendererProjectilesMixin

if TYPE_CHECKING:
    from ...game_world import GameWorld


@dataclass(slots=True)
class WorldRenderer(
    WorldRendererDrawMixin,
    WorldRendererEffectsMixin,
    WorldRendererProjectilesMixin,
    WorldRendererCreaturesMixin,
    WorldRendererOverlaysMixin,
    WorldRendererBonusesMixin,
    WorldRendererContextMixin,
):
    _world: GameWorld
    _render_frame: RenderFrame | None = None
    _small_font: SmallFontData | None = None
