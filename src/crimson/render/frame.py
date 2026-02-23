from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

from ..creatures.runtime import CreaturePool
from ..gameplay import GameplayState
from ..sim.state_types import PlayerState
from .rtx.mode import RtxRenderMode


@dataclass(frozen=True, slots=True)
class RenderFrame:
    """Typed world snapshot consumed by render code.

    This intentionally carries references (not deep copies) so render can be
    deterministic per frame boundary while remaining allocation-light.
    """

    assets_dir: Path

    world_size: float
    demo_mode_active: bool
    config: CrimsonConfig | None
    camera: Vec2
    ground: GroundRenderer | None

    state: GameplayState
    players: list[PlayerState]
    creatures: CreaturePool

    creature_textures: dict[str, rl.Texture]
    projs_texture: rl.Texture | None
    particles_texture: rl.Texture | None
    bullet_texture: rl.Texture | None
    bullet_trail_texture: rl.Texture | None
    arrow_texture: rl.Texture | None
    bonuses_texture: rl.Texture | None
    bodyset_texture: rl.Texture | None
    clock_table_texture: rl.Texture | None
    clock_pointer_texture: rl.Texture | None
    aim_texture: rl.Texture | None
    muzzle_flash_texture: rl.Texture | None
    wicons_texture: rl.Texture | None

    elapsed_ms: float
    bonus_anim_phase: float
    lan_player_rings_enabled: bool
    lan_local_aim_indicators_only: bool
    lan_local_player_slot_index: int
    rtx_mode: RtxRenderMode
