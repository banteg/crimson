from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from grim.geom import Vec2

from ..bonuses.update import bonus_update, bonus_update_pre_pickup_timers
from ..bonuses.pickup_fx import emit_bonus_pickup_effects
from ..camera import camera_shake_update
from ..creatures.damage import creature_apply_damage
from ..creatures.runtime import CREATURE_HITBOX_ALIVE, CreatureDeath, CreaturePool
from ..creatures.anim import creature_anim_advance_phase
from ..creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from ..effects import FxQueue, FxQueueRotated
from ..gameplay import (
    build_gameplay_state,
    player_update,
    survival_enforce_reward_weapon_guard,
    survival_progression_update,
)
from ..perks.runtime.effects import perks_update_effects
from ..perks.runtime.manifest import PLAYER_DEATH_HOOKS, WORLD_DT_STEPS
from ..perks.state import CreatureForPerks
from ..player_damage import player_take_projectile_damage
from ..projectiles import ProjectileHit
from .input import PlayerInput
from .input_frame import normalize_input_frame
from .presentation_step import (
    ProjectileDecalPostCtx,
    plan_death_sfx_keys,
    plan_hit_sfx_keys,
    queue_projectile_decals_post_hit,
    queue_projectile_decals_pre_hit,
)
from .state_types import BonusPickupEvent, GameplayState, PlayerState
from .world_defs import CREATURE_ANIM


@dataclass(slots=True)
class WorldEvents:
    hits: list[ProjectileHit]
    deaths: tuple[CreatureDeath, ...]
    pickups: list[BonusPickupEvent]
    sfx: list[str]
    trigger_game_tune: bool = False
    hit_sfx: list[str] = field(default_factory=list)
    death_sfx_preplanned: bool = False


_WORLD_DT_STEPS = WORLD_DT_STEPS
_PLAYER_DEATH_HOOKS = PLAYER_DEATH_HOOKS


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
        state = build_gameplay_state()
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
        apply_world_dt_steps: bool = True,
        dt_ms_i32: int | None = None,
        defer_camera_shake_update: bool = False,
        defer_freeze_corpse_fx: bool = False,
        mid_step_hook: Callable[[], None] | None = None,
        inputs: list[PlayerInput] | None,
        world_size: float,
        damage_scale_by_type: dict[int, float],
        detail_preset: int,
        fx_toggle: int = 0,
        fx_queue: FxQueue,
        fx_queue_rotated: FxQueueRotated,
        auto_pick_perks: bool,
        game_mode: int,
        perk_progression_enabled: bool,
        game_tune_started: bool = False,
        rng_marks: dict[str, int] | None = None,
    ) -> WorldEvents:
        def _mark(name: str) -> None:
            if rng_marks is None:
                return
            rng_marks[str(name)] = int(self.state.rng.state)

        dt = float(dt)
        if bool(apply_world_dt_steps):
            for step in _WORLD_DT_STEPS:
                dt = float(step(dt=dt, players=self.players))
        _mark("ws_begin")
        inputs = normalize_input_frame(inputs, player_count=len(self.players)).as_list()
        prev_positions = [(player.pos.x, player.pos.y) for player in self.players]
        prev_health = [float(player.health) for player in self.players]
        # Native Freeze pickup shatters corpses that existed at tick start;
        # same-tick kills are not included in that pass.
        freeze_corpse_indices_at_tick_start = {
            int(idx)
            for idx, creature in enumerate(self.creatures.entries)
            if creature.active and float(creature.hp) <= 0.0
        }
        perks_update_effects(self.state, self.players, dt, creatures=self.creatures.entries, fx_queue=fx_queue)
        _mark("ws_after_perk_effects")
        # `effects_update` runs early in the native frame loop, before creature/projectile updates.
        self.state.effects.update(dt, fx_queue=fx_queue)
        _mark("ws_after_effects_update")
        def _apply_projectile_damage_to_player(player_index: int, damage: float) -> None:
            idx = int(player_index)
            if not (0 <= idx < len(self.players)):
                return
            player_take_projectile_damage(self.state, self.players[idx], float(damage))
        creature_result = self.creatures.update(
            dt,
            dt_ms_i32=(int(dt_ms_i32) if dt_ms_i32 is not None else None),
            state=self.state,
            players=self.players,
            detail_preset=detail_preset,
            world_width=float(world_size),
            world_height=float(world_size),
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
        )
        _mark("ws_after_creatures")
        deaths = list(creature_result.deaths)
        planned_death_sfx: list[str] = []
        planned_death_sfx_cap = 5
        def _plan_death_sfx_now(death: CreatureDeath) -> None:
            keys = plan_death_sfx_keys([death], rand=self.state.rng.rand)
            if not keys:
                return
            remain = int(planned_death_sfx_cap) - len(planned_death_sfx)
            if remain <= 0:
                return
            planned_death_sfx.extend(keys[:remain])
        for death in deaths:
            _plan_death_sfx_now(death)
        trigger_game_tune = False
        hit_sfx: list[str] = []
        hit_audio_game_tune_started = bool(game_tune_started)
        def _apply_projectile_damage_to_creature(
            creature_index: int,
            damage: float,
            damage_type: int,
            impulse: Vec2,
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
                impulse=impulse,
                owner_id=int(owner_id),
                dt=float(dt),
                players=self.players,
                rand=self.state.rng.rand,
            )
            if killed and death_start_needed:
                self._record_creature_death(
                    creature_index=idx,
                    dt=float(dt),
                    detail_preset=int(detail_preset),
                    world_size=float(world_size),
                    fx_queue=fx_queue,
                    deaths=deaths,
                    plan_death_sfx_now=_plan_death_sfx_now,
                )
        def _on_secondary_detonation_kill(creature_index: int) -> None:
            idx = int(creature_index)
            if not (0 <= idx < len(self.creatures.entries)) or float(self.creatures.entries[idx].hp) > 0.0:
                return
            # Native detonation follow-up re-enters creature death handling but does
            # not run a second death-SFX random pick (`creature_apply_damage` only
            # does that on the original killing hit).
            self._record_creature_death(
                creature_index=idx,
                dt=float(dt),
                detail_preset=int(detail_preset),
                world_size=float(world_size),
                fx_queue=fx_queue,
                deaths=deaths,
                plan_death_sfx_now=_plan_death_sfx_now,
                plan_death_sfx=False,
            )
        def _on_projectile_hit_pre(hit: ProjectileHit) -> ProjectileDecalPostCtx:
            return self._prepare_projectile_hit_presentation(
                hit=hit,
                fx_queue=fx_queue,
                detail_preset=int(detail_preset),
                fx_toggle=int(fx_toggle),
            )
        def _on_projectile_hit_post(_hit: ProjectileHit, post_ctx: object | None) -> None:
            nonlocal trigger_game_tune, hit_audio_game_tune_started
            if not isinstance(post_ctx, ProjectileDecalPostCtx):
                return
            self._finalize_projectile_hit_presentation(
                post_ctx=post_ctx,
                fx_queue=fx_queue,
            )
            hit_trigger, keys = plan_hit_sfx_keys(
                [_hit],
                game_mode=int(game_mode),
                demo_mode_active=bool(self.state.demo_mode_active),
                game_tune_started=bool(hit_audio_game_tune_started),
                rand=self.state.rng.rand,
            )
            if hit_trigger:
                trigger_game_tune = True
                hit_audio_game_tune_started = True
            if keys:
                hit_sfx.extend(keys)
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
            on_hit=_on_projectile_hit_pre,
            on_hit_post=_on_projectile_hit_post,
        )
        _mark("ws_after_projectiles")
        _mark("ws_after_hit_sfx")
        self.state.secondary_projectiles.update_pulse_gun(
            dt,
            self.creatures.entries,
            apply_creature_damage=_apply_projectile_damage_to_creature,
            runtime_state=self.state,
            fx_queue=fx_queue,
            detail_preset=int(detail_preset),
            on_detonation_kill=_on_secondary_detonation_kill,
        )
        _mark("ws_after_secondary_projectiles")
        for idx, player in enumerate(self.players):
            if idx >= len(prev_health):
                continue
            if float(prev_health[idx]) < 0.0:
                continue
            if float(player.health) >= 0.0:
                continue
            for hook in _PLAYER_DEATH_HOOKS:
                hook(
                    state=self.state,
                    creatures=self.creatures,
                    players=self.players,
                    player=player,
                    dt=float(dt),
                    world_size=float(world_size),
                    detail_preset=int(detail_preset),
                    fx_queue=fx_queue,
                    deaths=deaths,
                )
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
            self._record_creature_death(
                creature_index=idx,
                dt=float(dt),
                detail_preset=int(detail_preset),
                world_size=float(world_size),
                fx_queue=fx_queue,
                deaths=deaths,
                plan_death_sfx_now=_plan_death_sfx_now,
                keep_corpse=False,
            )

        self.state.particles.update(
            dt,
            creatures=self.creatures.entries,
            apply_creature_damage=_apply_projectile_damage_to_creature,
            kill_creature=_kill_creature_no_corpse,
            fx_queue=fx_queue,
            sprite_effects=self.state.sprite_effects,
        )
        _mark("ws_after_particles_update")
        self.state.sprite_effects.update(dt)
        _mark("ws_after_sprite_effects")
        _mark("ws_after_particles")
        _mark("ws_after_death_sfx")

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
                creatures=self.creatures.entries,
            )
            if idx == 0:
                _mark("ws_after_player_update_p0")
        _mark("ws_after_player_update")
        if dt > 0.0:
            self._advance_creature_anim(dt)
            self._advance_player_anim(dt, prev_positions)
        if mid_step_hook is not None:
            mid_step_hook()
        if not bool(defer_camera_shake_update):
            camera_shake_update(self.state, dt)
        _mark("ws_after_camera_update")
        # Native level-up/perk-pending check runs before `bonus_update` in
        # gameplay_update_and_render. Keep the same ordering so XP awarded from
        # bonus-side kill paths (e.g. freeze cleanup) levels on the next tick.
        if perk_progression_enabled:
            survival_progression_update(
                self.state,
                self.players,
                game_mode=game_mode,
                auto_pick=auto_pick_perks,
                dt=dt,
                creatures=cast("list[CreatureForPerks]", self.creatures.entries),
            )
        _mark("ws_after_progression")
        # Native latches `time_scale_active` late (post mode update, pre bonus decrement); next-frame dt uses it.
        self.state.time_scale_active = float(self.state.bonuses.reflex_boost) > 0.0
        bonus_update_pre_pickup_timers(self.state, dt)
        pickups = bonus_update(
            self.state,
            self.players,
            dt,
            creatures=self.creatures.entries,
            update_hud=True,
            apply_creature_damage=_apply_projectile_damage_to_creature,
            detail_preset=int(detail_preset),
            defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
            freeze_corpse_indices=freeze_corpse_indices_at_tick_start,
        )
        if pickups:
            emit_bonus_pickup_effects(
                state=self.state,
                pickups=pickups,
                detail_preset=int(detail_preset),
            )
        survival_enforce_reward_weapon_guard(self.state, self.players)
        _mark("ws_after_bonus_update")
        sfx = list(planned_death_sfx)
        sfx.extend(creature_result.sfx)
        if self.state.sfx_queue:
            sfx.extend(self.state.sfx_queue)
            self.state.sfx_queue.clear()
        _mark("ws_after_sfx_queue_merge")
        # Player-damage VO RNG work lives inside `player_take_damage` for native
        # ordering parity (VO draw before heading-jitter draw).
        _mark("ws_after_player_damage_sfx")
        _mark("ws_after_sfx")

        return WorldEvents(
            hits=hits,
            deaths=tuple(deaths),
            pickups=pickups,
            sfx=sfx,
            trigger_game_tune=bool(trigger_game_tune),
            hit_sfx=hit_sfx,
            death_sfx_preplanned=True,
        )

    def _record_creature_death(
        self,
        *,
        creature_index: int,
        dt: float,
        detail_preset: int,
        world_size: float,
        fx_queue: FxQueue,
        deaths: list[CreatureDeath],
        plan_death_sfx_now: Callable[[CreatureDeath], None],
        keep_corpse: bool = True,
        plan_death_sfx: bool = True,
    ) -> None:
        death = self.creatures.handle_death(
            int(creature_index),
            state=self.state,
            players=self.players,
            rand=self.state.rng.rand,
            dt=float(dt),
            detail_preset=int(detail_preset),
            world_width=float(world_size),
            world_height=float(world_size),
            fx_queue=fx_queue,
            keep_corpse=bool(keep_corpse),
        )
        deaths.append(death)
        if bool(plan_death_sfx):
            plan_death_sfx_now(death)

    def _prepare_projectile_hit_presentation(
        self,
        hit: ProjectileHit,
        *,
        fx_queue: FxQueue,
        detail_preset: int,
        fx_toggle: int,
    ) -> ProjectileDecalPostCtx:
        return queue_projectile_decals_pre_hit(
            state=self.state,
            players=self.players,
            fx_queue=fx_queue,
            hit=hit,
            rand=self.state.rng.rand,
            detail_preset=int(detail_preset),
            fx_toggle=int(fx_toggle),
        )

    def _finalize_projectile_hit_presentation(
        self,
        *,
        post_ctx: ProjectileDecalPostCtx,
        fx_queue: FxQueue,
    ) -> None:
        queue_projectile_decals_post_hit(
            fx_queue=fx_queue,
            post_ctx=post_ctx,
            rand=self.state.rng.rand,
        )

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
            speed = Vec2(player.pos.x - prev_x, player.pos.y - prev_y).length()
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
