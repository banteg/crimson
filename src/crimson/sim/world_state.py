from __future__ import annotations

from dataclasses import dataclass
import math

from ..bonuses import BonusId
from ..creatures.runtime import CreaturePool
from ..creatures.anim import creature_anim_advance_phase
from ..creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from ..effects import FxQueue, FxQueueRotated
from ..gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_update,
    player_update,
    survival_progression_update,
)
from .world_defs import CREATURE_ANIM

ProjectileHit = tuple[int, float, float, float, float]


@dataclass(slots=True)
class WorldEvents:
    hits: list[ProjectileHit]
    deaths: tuple[object, ...]
    pickups: list[object]


@dataclass(slots=True)
class WorldState:
    spawn_env: SpawnEnv
    state: GameplayState
    players: list[PlayerState]
    creatures: CreaturePool

    @classmethod
    def build(
        cls,
        *,
        world_size: float,
        demo_mode_active: bool,
        hardcore: bool,
        difficulty_level: int,
    ) -> WorldState:
        spawn_env = SpawnEnv(
            terrain_width=float(world_size),
            terrain_height=float(world_size),
            demo_mode_active=bool(demo_mode_active),
            hardcore=bool(hardcore),
            difficulty_level=int(difficulty_level),
        )
        state = GameplayState()
        players: list[PlayerState] = []
        creatures = CreaturePool(env=spawn_env)
        return cls(
            spawn_env=spawn_env,
            state=state,
            players=players,
            creatures=creatures,
        )

    def step(
        self,
        dt: float,
        *,
        inputs: list[PlayerInput] | None,
        world_size: float,
        damage_scale_by_type: dict[int, float],
        detail_preset: int,
        fx_queue: FxQueue,
        fx_queue_rotated: FxQueueRotated,
        auto_pick_perks: bool,
        game_mode: int,
        perk_progression_enabled: bool,
    ) -> WorldEvents:
        if inputs is None:
            inputs = [PlayerInput() for _ in self.players]

        prev_positions = [(player.pos_x, player.pos_y) for player in self.players]

        # `effects_update` runs early in the native frame loop, before creature/projectile updates.
        self.state.effects.update(dt, fx_queue=fx_queue)

        hits = self.state.projectiles.update(
            dt,
            self.creatures.entries,
            world_size=float(world_size),
            damage_scale_by_type=damage_scale_by_type,
            rng=self.state.rng.rand,
            runtime_state=self.state,
        )
        self.state.secondary_projectiles.update_pulse_gun(dt, self.creatures.entries)

        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player_update(player, input_state, dt, self.state, world_size=float(world_size))

        creature_result = self.creatures.update(
            dt,
            state=self.state,
            players=self.players,
            detail_preset=detail_preset,
            world_width=float(world_size),
            world_height=float(world_size),
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
        )

        if dt > 0.0:
            self._advance_creature_anim(dt)
            self._advance_player_anim(dt, prev_positions)

        pickups = bonus_update(self.state, self.players, dt, creatures=self.creatures.entries, update_hud=True)
        if pickups:
            for pickup in pickups:
                self.state.effects.spawn_burst(
                    pos_x=float(pickup.pos_x),
                    pos_y=float(pickup.pos_y),
                    count=12,
                    rand=self.state.rng.rand,
                    detail_preset=detail_preset,
                    lifetime=0.4,
                    scale_step=0.1,
                    color_r=0.4,
                    color_g=0.5,
                    color_b=1.0,
                    color_a=0.5,
                )
                if pickup.bonus_id == int(BonusId.REFLEX_BOOST):
                    self.state.effects.spawn_ring(
                        pos_x=float(pickup.pos_x),
                        pos_y=float(pickup.pos_y),
                        detail_preset=detail_preset,
                        color_r=0.6,
                        color_g=0.6,
                        color_b=1.0,
                        color_a=1.0,
                    )
                elif pickup.bonus_id == int(BonusId.FREEZE):
                    self.state.effects.spawn_ring(
                        pos_x=float(pickup.pos_x),
                        pos_y=float(pickup.pos_y),
                        detail_preset=detail_preset,
                        color_r=0.3,
                        color_g=0.5,
                        color_b=0.8,
                        color_a=1.0,
                    )

        if perk_progression_enabled:
            survival_progression_update(self.state, self.players, game_mode=game_mode, auto_pick=auto_pick_perks)

        return WorldEvents(hits=hits, deaths=creature_result.deaths, pickups=pickups)

    def _advance_creature_anim(self, dt: float) -> None:
        for creature in self.creatures.entries:
            if not (creature.active and creature.hp > 0.0):
                continue
            try:
                type_id = CreatureTypeId(int(creature.type_id))
            except ValueError:
                continue
            info = CREATURE_ANIM.get(type_id)
            if info is None:
                continue
            creature.anim_phase, _ = creature_anim_advance_phase(
                creature.anim_phase,
                anim_rate=info.anim_rate,
                move_speed=float(creature.move_speed),
                dt=dt,
                size=float(creature.size),
                local_scale=float(getattr(creature, "move_scale", 1.0)),
                flags=creature.flags,
                ai_mode=int(creature.ai_mode),
            )

    def _advance_player_anim(self, dt: float, prev_positions: list[tuple[float, float]]) -> None:
        info = CREATURE_ANIM.get(CreatureTypeId.TROOPER)
        if info is None:
            return
        for idx, player in enumerate(self.players):
            if idx >= len(prev_positions):
                continue
            prev_x, prev_y = prev_positions[idx]
            speed = math.hypot(player.pos_x - prev_x, player.pos_y - prev_y)
            move_speed = speed / dt / 120.0 if dt > 0.0 else 0.0
            player.move_phase, _ = creature_anim_advance_phase(
                player.move_phase,
                anim_rate=info.anim_rate,
                move_speed=move_speed,
                dt=dt,
                size=float(player.size),
                local_scale=1.0,
                flags=CreatureFlags(0),
                ai_mode=0,
            )
