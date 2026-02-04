from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

from ..bonuses import BonusId
from ..creatures.damage import creature_apply_damage
from ..creatures.runtime import CreaturePool
from ..creatures.runtime import CREATURE_HITBOX_ALIVE
from ..creatures.anim import creature_anim_advance_phase
from ..creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from ..effects import FxQueue, FxQueueRotated
from ..gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_update,
    perk_active,
    perks_update_effects,
    player_update,
    survival_progression_update,
)
from ..perks import PerkId
from ..player_damage import player_take_projectile_damage
from .world_defs import CREATURE_ANIM

ProjectileHit = tuple[int, float, float, float, float, float, float]


@dataclass(slots=True)
class WorldEvents:
    hits: list[ProjectileHit]
    deaths: tuple[object, ...]
    pickups: list[object]
    sfx: list[str]


@dataclass(slots=True)
class _WorldDtCtx:
    dt: float
    players: list[PlayerState]


_WorldDtStep = Callable[[_WorldDtCtx], None]


def _world_dt_reflex_boosted(ctx: _WorldDtCtx) -> None:
    if ctx.dt > 0.0 and ctx.players and perk_active(ctx.players[0], PerkId.REFLEX_BOOSTED):
        ctx.dt *= 0.9


_WORLD_DT_STEPS: tuple[_WorldDtStep, ...] = (_world_dt_reflex_boosted,)


@dataclass(slots=True)
class _PlayerDeathCtx:
    state: GameplayState
    creatures: CreaturePool
    players: list[PlayerState]
    player_index: int
    player: PlayerState
    dt: float
    world_size: float
    detail_preset: int
    fx_queue: FxQueue
    deaths: list[object]


_PlayerDeathHook = Callable[[_PlayerDeathCtx], None]


def _player_death_final_revenge(ctx: _PlayerDeathCtx) -> None:
    player = ctx.player
    if not perk_active(player, PerkId.FINAL_REVENGE):
        return

    px = float(player.pos_x)
    py = float(player.pos_y)
    rand = ctx.state.rng.rand
    ctx.state.effects.spawn_explosion_burst(
        pos_x=px,
        pos_y=py,
        scale=1.8,
        rand=rand,
        detail_preset=int(ctx.detail_preset),
    )

    prev_guard = bool(ctx.state.bonus_spawn_guard)
    ctx.state.bonus_spawn_guard = True
    for creature_idx, creature in enumerate(ctx.creatures.entries):
        if not creature.active:
            continue
        if float(creature.hp) <= 0.0:
            continue

        dx = float(creature.x) - px
        dy = float(creature.y) - py
        if abs(dx) > 512.0 or abs(dy) > 512.0:
            continue

        remaining = 512.0 - math.hypot(dx, dy)
        if remaining <= 0.0:
            continue

        damage = remaining * 5.0
        death_start_needed = float(creature.hp) > 0.0 and float(creature.hitbox_size) == CREATURE_HITBOX_ALIVE
        killed = creature_apply_damage(
            creature,
            damage_amount=damage,
            damage_type=3,
            impulse_x=0.0,
            impulse_y=0.0,
            owner_id=-1 - int(player.index),
            dt=float(ctx.dt),
            players=ctx.players,
            rand=rand,
        )
        if killed and death_start_needed:
            ctx.deaths.append(
                ctx.creatures.handle_death(
                    int(creature_idx),
                    state=ctx.state,
                    players=ctx.players,
                    rand=rand,
                    detail_preset=int(ctx.detail_preset),
                    world_width=float(ctx.world_size),
                    world_height=float(ctx.world_size),
                    fx_queue=ctx.fx_queue,
                )
            )
    ctx.state.bonus_spawn_guard = prev_guard
    ctx.state.sfx_queue.append("sfx_explosion_large")
    ctx.state.sfx_queue.append("sfx_shockwave")


_PLAYER_DEATH_HOOKS: tuple[_PlayerDeathHook, ...] = (_player_death_final_revenge,)


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
        preserve_bugs: bool = False,
    ) -> WorldState:
        spawn_env = SpawnEnv(
            terrain_width=float(world_size),
            terrain_height=float(world_size),
            demo_mode_active=bool(demo_mode_active),
            hardcore=bool(hardcore),
            difficulty_level=int(difficulty_level),
        )
        state = GameplayState()
        state.demo_mode_active = bool(demo_mode_active)
        state.hardcore = bool(hardcore)
        state.preserve_bugs = bool(preserve_bugs)
        players: list[PlayerState] = []
        creatures = CreaturePool(env=spawn_env, effects=state.effects)
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
        dt_ctx = _WorldDtCtx(dt=float(dt), players=self.players)
        for step in _WORLD_DT_STEPS:
            step(dt_ctx)
        dt = float(dt_ctx.dt)

        if inputs is None:
            inputs = [PlayerInput() for _ in self.players]

        prev_positions = [(player.pos_x, player.pos_y) for player in self.players]
        prev_health = [float(player.health) for player in self.players]

        # Native runs `perks_update_effects` early in the frame loop and relies on the current aim position
        # (`player_state_table.aim_x/aim_y`). Our aim is otherwise updated inside `player_update`, so stage it here.
        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player.aim_x = float(input_state.aim_x)
            player.aim_y = float(input_state.aim_y)

        perks_update_effects(self.state, self.players, dt, creatures=self.creatures.entries, fx_queue=fx_queue)

        # `effects_update` runs early in the native frame loop, before creature/projectile updates.
        self.state.effects.update(dt, fx_queue=fx_queue)

        def _apply_projectile_damage_to_player(player_index: int, damage: float) -> None:
            idx = int(player_index)
            if not (0 <= idx < len(self.players)):
                return
            player_take_projectile_damage(self.state, self.players[idx], float(damage))

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

        deaths = list(creature_result.deaths)

        def _apply_projectile_damage_to_creature(
            creature_index: int,
            damage: float,
            damage_type: int,
            impulse_x: float,
            impulse_y: float,
            owner_id: int,
        ) -> None:
            idx = int(creature_index)
            if not (0 <= idx < len(self.creatures.entries)):
                return
            creature = self.creatures.entries[idx]
            if not creature.active:
                return

            death_start_needed = creature.hp > 0.0 and creature.hitbox_size == CREATURE_HITBOX_ALIVE
            killed = creature_apply_damage(
                creature,
                damage_amount=float(damage),
                damage_type=int(damage_type),
                impulse_x=float(impulse_x),
                impulse_y=float(impulse_y),
                owner_id=int(owner_id),
                dt=float(dt),
                players=self.players,
                rand=self.state.rng.rand,
            )
            if killed and death_start_needed:
                deaths.append(
                    self.creatures.handle_death(
                        idx,
                        state=self.state,
                        players=self.players,
                        rand=self.state.rng.rand,
                        detail_preset=int(detail_preset),
                        world_width=float(world_size),
                        world_height=float(world_size),
                        fx_queue=fx_queue,
                    )
                )

        hits = self.state.projectiles.update(
            dt,
            self.creatures.entries,
            world_size=float(world_size),
            damage_scale_by_type=damage_scale_by_type,
            detail_preset=int(detail_preset),
            rng=self.state.rng.rand,
            runtime_state=self.state,
            players=self.players,
            apply_player_damage=_apply_projectile_damage_to_player,
            apply_creature_damage=_apply_projectile_damage_to_creature,
        )
        self.state.secondary_projectiles.update_pulse_gun(
            dt,
            self.creatures.entries,
            apply_creature_damage=_apply_projectile_damage_to_creature,
            runtime_state=self.state,
            fx_queue=fx_queue,
            detail_preset=int(detail_preset),
        )

        for idx, player in enumerate(self.players):
            if idx >= len(prev_health):
                continue
            if float(prev_health[idx]) < 0.0:
                continue
            if float(player.health) >= 0.0:
                continue
            death_ctx = _PlayerDeathCtx(
                state=self.state,
                creatures=self.creatures,
                players=self.players,
                player_index=int(idx),
                player=player,
                dt=float(dt),
                world_size=float(world_size),
                detail_preset=int(detail_preset),
                fx_queue=fx_queue,
                deaths=deaths,
            )
            for hook in _PLAYER_DEATH_HOOKS:
                hook(death_ctx)

        def _kill_creature_no_corpse(creature_index: int, owner_id: int) -> None:
            idx = int(creature_index)
            if not (0 <= idx < len(self.creatures.entries)):
                return
            creature = self.creatures.entries[idx]
            if not creature.active:
                return
            if float(creature.hp) <= 0.0:
                return

            creature.last_hit_owner_id = int(owner_id)
            deaths.append(
                self.creatures.handle_death(
                    idx,
                    state=self.state,
                    players=self.players,
                    rand=self.state.rng.rand,
                    detail_preset=int(detail_preset),
                    world_width=float(world_size),
                    world_height=float(world_size),
                    fx_queue=fx_queue,
                    keep_corpse=False,
                )
            )

        self.state.particles.update(
            dt,
            creatures=self.creatures.entries,
            apply_creature_damage=_apply_projectile_damage_to_creature,
            kill_creature=_kill_creature_no_corpse,
            fx_queue=fx_queue,
            sprite_effects=self.state.sprite_effects,
        )
        self.state.sprite_effects.update(dt)

        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player_update(
                player,
                input_state,
                dt,
                self.state,
                detail_preset=int(detail_preset),
                world_size=float(world_size),
                players=self.players,
            )

        if dt > 0.0:
            self._advance_creature_anim(dt)
            self._advance_player_anim(dt, prev_positions)

        pickups = bonus_update(
            self.state,
            self.players,
            dt,
            creatures=self.creatures.entries,
            update_hud=True,
            apply_creature_damage=_apply_projectile_damage_to_creature,
            detail_preset=int(detail_preset),
        )
        if pickups:
            for pickup in pickups:
                if pickup.bonus_id != int(BonusId.NUKE):
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
            survival_progression_update(
                self.state,
                self.players,
                game_mode=game_mode,
                auto_pick=auto_pick_perks,
                dt=dt,
                creatures=self.creatures.entries,
            )

        sfx = list(creature_result.sfx)
        if self.state.sfx_queue:
            sfx.extend(self.state.sfx_queue)
            self.state.sfx_queue.clear()
        pain_sfx = ("sfx_trooper_inpain_01", "sfx_trooper_inpain_02", "sfx_trooper_inpain_03")
        death_sfx = ("sfx_trooper_die_01", "sfx_trooper_die_02")
        rand = self.state.rng.rand
        for idx, player in enumerate(self.players):
            if idx >= len(prev_health):
                continue
            before = float(prev_health[idx])
            after = float(player.health)
            if after >= before - 1e-6:
                continue
            if before <= 0.0:
                continue
            if after <= 0.0:
                # Prioritize death VO even if there are many other SFX this frame.
                sfx.insert(0, death_sfx[int(rand()) & 1])
            else:
                sfx.append(pain_sfx[int(rand()) % len(pain_sfx)])

        return WorldEvents(hits=hits, deaths=tuple(deaths), pickups=pickups, sfx=sfx)

    def _advance_creature_anim(self, dt: float) -> None:
        if float(self.state.bonuses.freeze) > 0.0:
            return
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
