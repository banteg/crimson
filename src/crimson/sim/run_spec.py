from __future__ import annotations

import msgspec

from grim.geom import Vec2

from ..game_modes import GameMode
from ..msgspec_types import NonNegativeInt, PlayerCount, PositiveFloat, PositiveInt
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel


class CreatureSlotResidue(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Persistent creature-slot state inherited at run start.

    Native `creature_reset_all` (0x4281e0) clears `active` and detaches linked
    spawn-slot owners; every other creature field keeps the previous
    occupant's value, and spawn paths overwrite only what they write. Captured
    at the run-setup latch so replays can seed an identical pool."""

    index: int
    phase_seed: int = 0
    state_flag: int = 0
    collision_flag: int = 0
    collision_timer: float = 0.0
    lifecycle_stage: float = 0.0
    pos: Vec2 = msgspec.field(default_factory=Vec2)
    vel: Vec2 = msgspec.field(default_factory=Vec2)
    hp: float = 0.0
    max_hp: float = 0.0
    heading: float = 0.0
    target_heading: float = 0.0
    size: float = 0.0
    hit_flash_timer: float = 0.0
    tint_r: float = 0.0
    tint_g: float = 0.0
    tint_b: float = 0.0
    tint_a: float = 0.0
    force_target: int = 0
    target: Vec2 = msgspec.field(default_factory=Vec2)
    contact_damage: float = 0.0
    move_speed: float = 0.0
    attack_cooldown: float = 0.0
    reward_value: float = 0.0
    type_id: int = 0
    target_player: int = 0
    link_index: int = 0
    target_offset: Vec2 = msgspec.field(default_factory=Vec2)
    orbit_angle: float = 0.0
    # Union field in native (radius f32 / projectile type id); raw bits.
    orbit_radius_u32: int = 0
    flags: int = 0
    ai_mode: int = 0
    anim_phase: float = 0.0


class RunSpec(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Inputs captured before any run-start mutation, shared by live and replay."""

    game_mode_id: GameMode
    seed: int
    quest_level: QuestLevel | None = None
    typo_dictionary_words: tuple[str, ...] = ()
    typo_highscore_names: tuple[str, ...] = ()
    tick_rate: PositiveInt = 60
    # Mirrors the native quest retry scaling counter (`quest_fail_retry_count`).
    quest_fail_retry_count: NonNegativeInt = 0
    hardcore: bool = False
    preserve_bugs: bool = False
    detail_preset: NonNegativeInt = 5
    violence_disabled: NonNegativeInt = 0
    world_size: PositiveFloat = 1024.0
    player_count: PlayerCount = 1
    status: GameStatusData = msgspec.field(default_factory=GameStatusData)
    # Creature pool residue at run start for original captures; None for
    # port-recorded replays, which start from a fresh pool.
    initial_creature_pool: tuple[CreatureSlotResidue, ...] | None = None
