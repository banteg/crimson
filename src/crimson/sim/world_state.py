from __future__ import annotations

from typing import cast

import msgspec

from grim.geom import Vec2
from grim.sfx_map import SfxId

from ..bonuses.pickup_fx import emit_bonus_pickup_effects
from ..bonuses.update import bonus_update, bonus_update_pre_pickup_timers
from ..camera import camera_shake_update
from ..creatures.anim import creature_anim_advance_phase
from ..creatures.damage import creature_apply_damage_with_lethal_followup
from ..creatures.damage_runtime import CreatureDamageRuntime
from ..creatures.runtime import CreatureDeath, CreaturePool, CreatureUpdateOptions
from ..creatures.spawn import CreatureAiMode, CreatureFlags, CreatureTypeId, SpawnEnv
from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..gameplay import (
    build_gameplay_state,
    player_frame_dt_after_roundtrip,
    player_update,
    survival_enforce_reward_weapon_guard,
    survival_progression_update,
)
from ..owner_ref import OwnerRef
from ..perks.runtime.effects import perks_update_effects
from ..perks.runtime.manifest import PLAYER_DEATH_HOOKS, WORLD_DT_STEPS
from ..player_damage import PlayerDeathRuntime, player_take_projectile_damage
from ..projectiles.runtime import PrimaryStepCtx, ProjectileHitRuntime, ProjectileUpdateOptions, SecondaryStepCtx
from ..projectiles.types import ProjectileHit
from .input import PlayerInput
from .input_frame import normalize_input_frame
from .presentation_step import (
    ProjectileDecalPostCtx,
    plan_hit_sfx,
    queue_projectile_decals_post_hit,
    queue_projectile_decals_pre_hit,
)
from .state_types import BonusPickupEvent, GameplayState, PlayerState
from .world_defs import CREATURE_ANIM


class WorldEvents(msgspec.Struct):
    hits: list[ProjectileHit]
    deaths: tuple[CreatureDeath, ...]
    pickups: list[BonusPickupEvent]
    sfx: list[SfxId]
    trigger_game_tune: bool = False
    hit_sfx: list[SfxId] = msgspec.field(default_factory=list)


class WorldMidStepRuntime(msgspec.Struct):
    def run_mid_step(self) -> None:
        return None


_WORLD_DT_STEPS = WORLD_DT_STEPS
_PLAYER_DEATH_HOOKS = PLAYER_DEATH_HOOKS


class _WorldStepRuntime(ProjectileHitRuntime, CreatureDamageRuntime, PlayerDeathRuntime):
    world: WorldState
    dt: float
    world_size: float
    detail_preset: int
    violence_disabled: int
    fx_queue: FxQueue
    game_mode: GameMode
    hit_audio_game_tune_started: bool
    deaths: list[CreatureDeath]
    sfx: list[SfxId]
    trigger_game_tune: bool = False
    hit_sfx: list[SfxId] = msgspec.field(default_factory=list)

    def apply_player_projectile_damage(self, player_index: int, damage: float) -> None:
        idx = int(player_index)
        if not (0 <= idx < len(self.world.players)):
            return
        player_take_projectile_damage(self.world.state, self.world.players[idx], float(damage))

    def apply_player_damage(self, player_index: int, damage: float) -> None:
        self.apply_player_projectile_damage(player_index, damage)

    def apply_creature_damage(
        self,
        creature_index: int,
        damage: float,
        damage_type: int,
        impulse: Vec2,
        owner: OwnerRef,
    ) -> None:
        idx = int(creature_index)
        if not (0 <= idx < len(self.world.creatures.entries)):
            return
        creature = self.world.creatures.entries[idx]
        if not creature.active:
            return
        creature_apply_damage_with_lethal_followup(
            creature,
            creature_index=idx,
            damage_amount=float(damage),
            damage_type=int(damage_type),
            impulse=impulse,
            owner=owner,
            dt=float(self.dt),
            players=self.world.players,
            rng=self.world.state.rng,
            preserve_bugs=bool(self.world.state.preserve_bugs),
            effects=self.world.state.effects,
            detail_preset=int(self.detail_preset),
            creature_damage_runtime=self,
        )

    def on_creature_lethal(self, creature_index: int, death_sfx: tuple[SfxId, ...]) -> None:
        self.world._record_creature_death(
            creature_index=int(creature_index),
            dt=float(self.dt),
            detail_preset=int(self.detail_preset),
            world_size=float(self.world_size),
            fx_queue=self.fx_queue,
            deaths=self.deaths,
            sfx=self.sfx,
            death_sfx=death_sfx,
        )

    def on_secondary_detonation_kill(self, creature_index: int) -> None:
        idx = int(creature_index)
        if not (0 <= idx < len(self.world.creatures.entries)) or float(self.world.creatures.entries[idx].hp) > 0.0:
            return
        # Native detonation follow-up re-enters creature death handling but does
        # not run a second death-SFX random pick (`creature_apply_damage` only
        # does that on the original killing hit).
        self.world._record_creature_death(
            creature_index=idx,
            dt=float(self.dt),
            detail_preset=int(self.detail_preset),
            world_size=float(self.world_size),
            fx_queue=self.fx_queue,
            deaths=self.deaths,
            sfx=self.sfx,
        )

    def prepare_projectile_hit_presentation(self, hit: ProjectileHit) -> ProjectileDecalPostCtx:
        return self.world._prepare_projectile_hit_presentation(
            hit=hit,
            fx_queue=self.fx_queue,
            detail_preset=int(self.detail_preset),
            violence_disabled=int(self.violence_disabled),
        )

    def finalize_projectile_hit_presentation(self, hit: ProjectileHit, post_ctx: object) -> None:
        decal_post_ctx = cast("ProjectileDecalPostCtx", post_ctx)
        self.world._finalize_projectile_hit_presentation(
            post_ctx=decal_post_ctx,
            fx_queue=self.fx_queue,
        )
        hit_trigger, keys = plan_hit_sfx(
            [hit],
            game_mode=self.game_mode,
            demo_mode_active=self.world.state.demo_mode_active,
            game_tune_started=self.hit_audio_game_tune_started,
            rng=self.world.state.rng,
        )
        if hit_trigger:
            self.trigger_game_tune = True
            self.hit_audio_game_tune_started = True
        if keys:
            self.hit_sfx.extend(keys)

    def begin_hit_presentation(self, hit: ProjectileHit) -> ProjectileDecalPostCtx:
        return self.prepare_projectile_hit_presentation(hit)

    def finish_hit_presentation(self, hit: ProjectileHit, presentation: object) -> None:
        self.finalize_projectile_hit_presentation(hit, presentation)

    def kill_creature_no_corpse(self, creature_index: int, owner: OwnerRef) -> None:
        idx = int(creature_index)
        if not (0 <= idx < len(self.world.creatures.entries)):
            return
        creature = self.world.creatures.entries[idx]
        if not creature.active:
            return
        if float(creature.hp) <= 0.0:
            return
        creature.last_hit_owner = owner
        self.world._record_creature_death(
            creature_index=idx,
            dt=float(self.dt),
            detail_preset=int(self.detail_preset),
            world_size=float(self.world_size),
            fx_queue=self.fx_queue,
            deaths=self.deaths,
            sfx=self.sfx,
            keep_corpse=False,
        )

    def on_player_lethal(self, player: PlayerState, *, dt: float) -> None:
        self.world._run_player_death_hooks(
            player=player,
            dt=float(dt),
            world_size=float(self.world_size),
            detail_preset=int(self.detail_preset),
            fx_queue=self.fx_queue,
            deaths=self.deaths,
        )

    def build_events(self, *, hits: list[ProjectileHit], pickups: list[BonusPickupEvent]) -> WorldEvents:
        return WorldEvents(
            hits=hits,
            deaths=tuple(self.deaths),
            pickups=pickups,
            sfx=self.sfx,
            trigger_game_tune=bool(self.trigger_game_tune),
            hit_sfx=self.hit_sfx,
        )


class WorldState(msgspec.Struct):
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
        quest_fail_retry_count: int,
        preserve_bugs: bool = False,
    ) -> WorldState:
        spawn_env = SpawnEnv(
            terrain_width=float(world_size),
            terrain_height=float(world_size),
            demo_mode_active=demo_mode_active,
            hardcore=hardcore,
            quest_fail_retry_count=int(quest_fail_retry_count),
        )
        state = build_gameplay_state()
        state.demo_mode_active = demo_mode_active
        state.hardcore = hardcore
        state.preserve_bugs = preserve_bugs
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
        dt_player_local: float | None = None,
        defer_camera_shake_update: bool = False,
        defer_freeze_corpse_fx: bool = False,
        mid_step_runtime: WorldMidStepRuntime | None = None,
        inputs: list[PlayerInput] | None,
        world_size: float,
        damage_scale_by_type: dict[int, float],
        detail_preset: int,
        violence_disabled: int = 0,
        fx_queue: FxQueue,
        fx_queue_rotated: FxQueueRotated,
        game_mode: GameMode,
        perk_progression_enabled: bool,
        game_tune_started: bool = False,
    ) -> WorldEvents:
        dt = float(dt)
        fx_queue.violence_disabled = int(violence_disabled)
        self.state.player_death_hook_skip_indices.clear()
        if apply_world_dt_steps:
            for step in _WORLD_DT_STEPS:
                dt = float(step(dt=dt, players=self.players))
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
        # `effects_update` runs early in the native frame loop, before creature/projectile updates.
        self.state.effects.update(dt, fx_queue=fx_queue)

        creature_result = self.creatures.update(
            dt,
            options=CreatureUpdateOptions(
                state=self.state,
                players=self.players,
                rng=self.state.rng,
                env=self.spawn_env,
                world_width=float(world_size),
                world_height=float(world_size),
                fx_queue=fx_queue,
                fx_queue_rotated=fx_queue_rotated,
                detail_preset=int(detail_preset),
                violence_disabled=int(violence_disabled),
            ),
        )
        step_runtime = _WorldStepRuntime(
            world=self,
            dt=float(dt),
            world_size=float(world_size),
            detail_preset=int(detail_preset),
            violence_disabled=int(violence_disabled),
            fx_queue=fx_queue,
            game_mode=game_mode,
            hit_audio_game_tune_started=bool(game_tune_started),
            deaths=list(creature_result.deaths),
            sfx=list(creature_result.sfx),
        )
        hits = self.state.projectiles.step(
            PrimaryStepCtx(
                dt=float(dt),
                creatures=self.creatures.entries,
                options=ProjectileUpdateOptions(
                    world_size=float(world_size),
                    damage_scale_by_type=damage_scale_by_type,
                    detail_preset=int(detail_preset),
                    rng=self.state.rng,
                    runtime_state=self.state,
                    players=self.players,
                    hit_runtime=step_runtime,
                    creature_damage_runtime=step_runtime,
                ),
            ),
        )
        self.state.secondary_projectiles.step(
            SecondaryStepCtx(
                dt=float(dt),
                creatures=self.creatures.entries,
                runtime_state=self.state,
                fx_queue=fx_queue,
                detail_preset=int(detail_preset),
                creature_damage_runtime=step_runtime,
            ),
        )
        self._run_post_damage_player_death_hooks(
            prev_health=prev_health,
            dt=float(dt),
            world_size=float(world_size),
            detail_preset=int(detail_preset),
            fx_queue=fx_queue,
            deaths=step_runtime.deaths,
        )

        self.state.particles.update(
            dt,
            creatures=self.creatures.entries,
            creature_damage_runtime=step_runtime,
            fx_queue=fx_queue,
            sprite_effects=self.state.sprite_effects,
        )
        self.state.sprite_effects.update(dt)
        reload_active_any = any(bool(entry.reload_down) or bool(entry.reload_pressed) for entry in inputs)
        player_dt = float(dt)
        if dt_player_local is not None:
            player_dt = float(dt_player_local)
        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player_update(
                player,
                input_state,
                player_dt,
                self.state,
                detail_preset=int(detail_preset),
                world_size=float(world_size),
                players=self.players,
                creatures=self.creatures.entries,
                spawn_slots=self.creatures.spawn_slots,
                player_death_runtime=step_runtime,
                reload_active_any=bool(reload_active_any),
            )
            if dt_player_local is None:
                player_dt = player_frame_dt_after_roundtrip(
                    dt=player_dt,
                    time_scale_active=bool(self.state.time_scale_active),
                    reflex_boost_timer=float(self.state.bonuses.reflex_boost),
                )
        dt = float(player_dt)
        if dt > 0.0:
            self._advance_creature_anim(dt)
            self._advance_player_anim(dt, prev_positions)
        if mid_step_runtime is not None:
            mid_step_runtime.run_mid_step()
        if not bool(defer_camera_shake_update):
            camera_shake_update(self.state, dt)
        # Native level-up/perk-pending check runs before `bonus_update` in
        # gameplay_update_and_render. Keep the same ordering so XP awarded from
        # bonus-side kill paths (e.g. freeze cleanup) levels on the next tick.
        if perk_progression_enabled:
            survival_progression_update(
                self.state,
                self.players,
            )
        # Native latches `time_scale_active` late (post mode update, pre bonus decrement); next-frame dt uses it.
        self.state.time_scale_active = float(self.state.bonuses.reflex_boost) > 0.0
        bonus_update_pre_pickup_timers(self.state, dt)
        pickups = bonus_update(
            self.state,
            self.players,
            dt,
            creatures=self.creatures.entries,
            update_hud=True,
            detail_preset=int(detail_preset),
            defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
            freeze_corpse_indices=freeze_corpse_indices_at_tick_start,
            creature_damage_runtime=step_runtime,
        )
        if pickups:
            emit_bonus_pickup_effects(
                state=self.state,
                pickups=pickups,
                detail_preset=int(detail_preset),
            )
        survival_enforce_reward_weapon_guard(self.state, self.players)
        if self.state.sfx_queue:
            step_runtime.sfx.extend(self.state.sfx_queue)
            self.state.sfx_queue.clear()
        # Player-damage VO RNG work lives inside `player_take_damage` for native
        # ordering parity (VO draw before heading-jitter draw).
        self.state.player_death_hook_skip_indices.clear()
        return step_runtime.build_events(hits=hits, pickups=pickups)

    def _run_player_death_hooks(
        self,
        *,
        player: PlayerState,
        dt: float,
        world_size: float,
        detail_preset: int,
        fx_queue: FxQueue,
        deaths: list[CreatureDeath],
    ) -> None:
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

    def _run_post_damage_player_death_hooks(
        self,
        *,
        prev_health: list[float],
        dt: float,
        world_size: float,
        detail_preset: int,
        fx_queue: FxQueue,
        deaths: list[CreatureDeath],
    ) -> None:
        for idx, player in enumerate(self.players):
            if idx >= len(prev_health):
                continue
            if float(prev_health[idx]) < 0.0:
                continue
            if float(player.health) >= 0.0:
                continue
            player_idx = int(player.index)
            if player_idx in self.state.player_death_hook_skip_indices:
                self.state.player_death_hook_skip_indices.discard(player_idx)
                continue
            self._run_player_death_hooks(
                player=player,
                dt=float(dt),
                world_size=float(world_size),
                detail_preset=int(detail_preset),
                fx_queue=fx_queue,
                deaths=deaths,
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
        keep_corpse: bool = True,
        sfx: list[SfxId],
        death_sfx: tuple[SfxId, ...] = (),
    ) -> None:
        death = self.creatures.handle_death(
            int(creature_index),
            state=self.state,
            players=self.players,
            rng=self.state.rng,
            dt=float(dt),
            detail_preset=int(detail_preset),
            world_width=float(world_size),
            world_height=float(world_size),
            fx_queue=fx_queue,
            keep_corpse=bool(keep_corpse),
        )
        deaths.append(death)
        sfx.extend(death_sfx)

    def _prepare_projectile_hit_presentation(
        self,
        hit: ProjectileHit,
        *,
        fx_queue: FxQueue,
        detail_preset: int,
        violence_disabled: int,
    ) -> ProjectileDecalPostCtx:
        return queue_projectile_decals_pre_hit(
            state=self.state,
            players=self.players,
            fx_queue=fx_queue,
            hit=hit,
            rng=self.state.rng,
            detail_preset=int(detail_preset),
            violence_disabled=int(violence_disabled),
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
            rng=self.state.rng,
        )

    def _advance_creature_anim(self, dt: float) -> None:
        if float(self.state.bonuses.freeze) > 0.0:
            return
        for creature in self.creatures.entries:
            if not (creature.active and creature.hp > 0.0):
                continue
            type_id = creature.type_id
            info = CREATURE_ANIM[type_id]
            creature.anim_phase, _ = creature_anim_advance_phase(
                creature.anim_phase,
                anim_rate=info.anim_rate,
                move_speed=float(creature.move_speed),
                dt=dt,
                size=float(creature.size),
                local_scale=float(creature.move_scale),
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
                ai_mode=CreatureAiMode.ORBIT_PLAYER,
            )
