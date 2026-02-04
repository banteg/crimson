from __future__ import annotations

from dataclasses import dataclass, field
import math
from pathlib import Path

from ..creatures.spawn import advance_survival_spawn_stage, tick_survival_wave_spawns
from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    perks_rebuild_available,
    weapon_assign_player,
    weapon_refresh_available,
)
from ..persistence.save_status import GameStatus, default_status_blob, parse_status_blob
from ..weapons import WEAPON_TABLE
from .projectile_decals import queue_projectile_decals
from .world_state import WorldEvents, WorldState


def _damage_scale_by_weapon_id() -> dict[int, float]:
    damage_scale_by_type: dict[int, float] = {}
    for entry in WEAPON_TABLE:
        if int(entry.weapon_id) <= 0:
            continue
        damage_scale_by_type[int(entry.weapon_id)] = float(entry.damage_scale or 1.0)
    return damage_scale_by_type


def _init_default_players(players: list[PlayerState], *, world_size: float, player_count: int) -> None:
    world_size = float(world_size)
    count = max(1, int(player_count))
    base_x = world_size * 0.5
    base_y = world_size * 0.5

    if count <= 1:
        offsets = [(0.0, 0.0)]
    else:
        radius = 32.0
        step = math.tau / float(count)
        offsets = [
            (math.cos(float(idx) * step) * radius, math.sin(float(idx) * step) * radius) for idx in range(count)
        ]

    for idx in range(count):
        offset_x, offset_y = offsets[idx]
        x = base_x + float(offset_x)
        y = base_y + float(offset_y)
        x = max(0.0, min(world_size, x))
        y = max(0.0, min(world_size, y))
        player = PlayerState(index=idx, pos_x=x, pos_y=y)
        weapon_assign_player(player, 1)
        players.append(player)


def _init_players_from_inits(players: list[PlayerState], inits: list[tuple[float, float, int]]) -> None:
    for idx, (pos_x, pos_y, weapon_id) in enumerate(inits):
        player = PlayerState(index=int(idx), pos_x=float(pos_x), pos_y=float(pos_y))
        weapon_assign_player(player, int(weapon_id))
        players.append(player)


def _apply_reflex_boost_time_scale(dt: float, state: GameplayState) -> float:
    dt = float(dt)
    if dt <= 0.0:
        return 0.0
    timer = float(state.bonuses.reflex_boost)
    if timer <= 0.0:
        return dt
    time_scale_factor = 0.3
    if timer < 1.0:
        time_scale_factor = (1.0 - timer) * 0.7 + 0.3
    return dt * time_scale_factor


@dataclass(slots=True)
class SurvivalSessionState:
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown: float = 0.0


@dataclass(slots=True)
class SurvivalSession:
    world: WorldState
    world_size: float
    detail_preset: int = 5
    fx_toggle: int = 0
    auto_pick_perks: bool = False
    perk_progression_enabled: bool = True

    damage_scale_by_type: dict[int, float] = field(default_factory=_damage_scale_by_weapon_id)
    fx_queue: FxQueue = field(default_factory=FxQueue)
    fx_queue_rotated: FxQueueRotated = field(default_factory=FxQueueRotated)
    state: SurvivalSessionState = field(default_factory=SurvivalSessionState)

    tick: int = 0
    last_dt: float = 0.0

    @classmethod
    def build(
        cls,
        *,
        world_size: float = 1024.0,
        player_count: int = 1,
        player_inits: list[tuple[float, float, int]] | None = None,
        rng_state: int = 0xBEEF,
        status_blob: bytes | None = None,
        demo_mode_active: bool = False,
        hardcore: bool = False,
        difficulty_level: int = 0,
        preserve_bugs: bool = False,
        detail_preset: int = 5,
        fx_toggle: int = 0,
        auto_pick_perks: bool = False,
        perk_progression_enabled: bool = True,
    ) -> SurvivalSession:
        world = WorldState.build(
            world_size=float(world_size),
            demo_mode_active=bool(demo_mode_active),
            hardcore=bool(hardcore),
            difficulty_level=int(difficulty_level),
            preserve_bugs=bool(preserve_bugs),
        )
        world.state.rng.srand(int(rng_state))
        if status_blob is not None:
            blob = bytes(status_blob)
            if len(blob) != len(default_status_blob()):
                blob = default_status_blob()
            try:
                data = parse_status_blob(blob)
            except Exception:
                data = parse_status_blob(default_status_blob())
            world.state.status = GameStatus(path=Path("<demo>"), data=data, dirty=False)
        if player_inits is not None:
            _init_players_from_inits(world.players, list(player_inits))
        else:
            _init_default_players(world.players, world_size=float(world_size), player_count=int(player_count))
        return cls(
            world=world,
            world_size=float(world_size),
            detail_preset=int(detail_preset),
            fx_toggle=int(fx_toggle),
            auto_pick_perks=bool(auto_pick_perks),
            perk_progression_enabled=bool(perk_progression_enabled),
        )

    def is_game_over(self) -> bool:
        return bool(self.world.players) and all(float(p.health) <= 0.0 for p in self.world.players)

    def step(self, dt: float, *, inputs: list[PlayerInput] | None = None) -> WorldEvents:
        state = self.world.state
        state.game_mode = int(GameMode.SURVIVAL)
        state.demo_mode_active = bool(self.world.spawn_env.demo_mode_active)

        weapon_refresh_available(state)
        perks_rebuild_available(state)

        dt_scaled = _apply_reflex_boost_time_scale(dt, state)
        self.last_dt = float(dt_scaled)

        if dt_scaled > 0.0:
            self.state.elapsed_ms += float(dt_scaled) * 1000.0

        events = self.world.step(
            dt_scaled,
            inputs=inputs,
            world_size=float(self.world_size),
            damage_scale_by_type=self.damage_scale_by_type,
            detail_preset=int(self.detail_preset),
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            auto_pick_perks=bool(self.auto_pick_perks),
            game_mode=int(GameMode.SURVIVAL),
            perk_progression_enabled=bool(self.perk_progression_enabled),
        )

        if events.hits:
            queue_projectile_decals(
                state=state,
                players=self.world.players,
                hits=events.hits,
                fx_queue=self.fx_queue,
                detail_preset=int(self.detail_preset),
                fx_toggle=int(self.fx_toggle),
            )

        if dt_scaled > 0.0 and self.world.players:
            player = self.world.players[0]

            stage, milestone_calls = advance_survival_spawn_stage(self.state.stage, player_level=int(player.level))
            self.state.stage = int(stage)
            for call in milestone_calls:
                self.world.creatures.spawn_template(
                    int(call.template_id),
                    call.pos,
                    float(call.heading),
                    state.rng,
                    rand=state.rng.rand,
                )

            cooldown, wave_spawns = tick_survival_wave_spawns(
                float(self.state.spawn_cooldown),
                float(dt_scaled) * 1000.0,
                state.rng,
                player_count=len(self.world.players),
                survival_elapsed_ms=float(self.state.elapsed_ms),
                player_experience=int(player.experience),
                terrain_width=int(self.world_size),
                terrain_height=int(self.world_size),
            )
            self.state.spawn_cooldown = float(cooldown)
            self.world.creatures.spawn_inits(wave_spawns)

        self.tick += 1
        return events
