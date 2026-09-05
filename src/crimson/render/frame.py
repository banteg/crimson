from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.assets import RuntimeResources
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer

from ..creatures.runtime import CreaturePool
from ..sim.state_types import PlayerState
from .rtx.mode import RtxRenderMode

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState



class RenderFrame(msgspec.Struct, frozen=True):
    """Typed world snapshot consumed by render code.

    This intentionally carries references (not deep copies) so render can be
    deterministic per frame boundary while remaining allocation-light.
    """

    world_size: float
    demo_mode_active: bool
    config: CrimsonConfig | None
    camera: Vec2
    ground: GroundRenderer | None

    state: GameplayState
    players: list[PlayerState]
    creatures: CreaturePool
    resources: RuntimeResources

    elapsed_ms: float
    bonus_anim_phase: float
    rtx_mode: RtxRenderMode
