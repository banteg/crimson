from __future__ import annotations

from dataclasses import dataclass, field

from grim.geom import Vec2

from ..camera import camera_shake_update
from ..creatures.damage import creature_apply_damage
from ..creatures.runtime import CREATURE_HITBOX_ALIVE, CreatureDeath, CreaturePool
from ..creatures.anim import creature_anim_advance_phase
from ..creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from ..effects import FxQueue, FxQueueRotated
from ..features.bonuses import emit_bonus_pickup_effects
from ..features.perks import PLAYER_DEATH_HOOKS, WORLD_DT_STEPS
from ..gameplay import (
    BonusPickupEvent,
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_update,
    bonus_update_pre_pickup_timers,
    perks_update_effects,
    player_update,
    survival_progression_update,
)
from ..player_damage import player_take_projectile_damage
from ..projectiles import ProjectileHit
from .input_frame import normalize_input_frame
from .presentation_step import (
    ProjectileDecalPostCtx,
    plan_death_sfx_keys,
    plan_hit_sfx_keys,
    queue_projectile_decals_post_hit,
    queue_projectile_decals_pre_hit,
)
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
        for step in _WORLD_DT_STEPS:
            dt = float(step(dt=dt, players=self.players))
        _mark("ws_begin")
        inputs = normalize_input_frame(inputs, player_count=len(self.players)).as_list()

        prev_positions = [(player.pos.x, player.pos.y) for player in self.players]
        prev_health = [float(player.health) for player in self.players]

        # Native runs `perks_update_effects` early in the frame loop and relies on the current aim position.
        # Our aim is otherwise updated inside `player_update`, so stage it here.
        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player.aim = input_state.aim

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
        planned_death_sfx_cap = 3

        def _plan_death_sfx_now(death: CreatureDeath) -> None:
            if len(planned_death_sfx) >= planned_death_sfx_cap:
                return
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
                death = self.creatures.handle_death(
                    idx,
                    state=self.state,
                    players=self.players,
                    rand=self.state.rng.rand,
                    dt=float(dt),
                    detail_preset=int(detail_preset),
                    world_width=float(world_size),
                    world_height=float(world_size),
                    fx_queue=fx_queue,
                )
                deaths.append(death)
                _plan_death_sfx_now(death)

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
            death = self.creatures.handle_death(
                idx,
                state=self.state,
                players=self.players,
                rand=self.state.rng.rand,
                dt=float(dt),
                detail_preset=int(detail_preset),
                world_width=float(world_size),
                world_height=float(world_size),
                fx_queue=fx_queue,
                keep_corpse=False,
            )
            deaths.append(death)
            _plan_death_sfx_now(death)

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
            )
            if idx == 0:
                _mark("ws_after_player_update_p0")
        _mark("ws_after_player_update")

        if dt > 0.0:
            self._advance_creature_anim(dt)
            self._advance_player_anim(dt, prev_positions)

        camera_shake_update(self.state, dt)
        bonus_update_pre_pickup_timers(self.state, dt)

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
            emit_bonus_pickup_effects(
                state=self.state,
                pickups=pickups,
                detail_preset=int(detail_preset),
            )
        _mark("ws_after_bonus_update")

        if perk_progression_enabled:
            survival_progression_update(
                self.state,
                self.players,
                game_mode=game_mode,
                auto_pick=auto_pick_perks,
                dt=dt,
                creatures=self.creatures.entries,
            )
        _mark("ws_after_progression")

        sfx = list(planned_death_sfx)
        sfx.extend(creature_result.sfx)
        if self.state.sfx_queue:
            sfx.extend(self.state.sfx_queue)
            self.state.sfx_queue.clear()
        _mark("ws_after_sfx_queue_merge")
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
