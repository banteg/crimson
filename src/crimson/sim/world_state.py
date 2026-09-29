from __future__ import annotations

from collections.abc import Sequence

import msgspec

from crimson.sim.gameplay_state import GameplayState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..bonuses.update import bonus_telekinetic_update, bonus_update, bonus_update_pre_pickup_timers
from ..camera import camera_shake_update
from ..creatures.damage import creature_death_sfx_for_slot
from ..creatures.runtime import CreatureDeath, CreaturePool
from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..gameplay import (
    gameplay_accumulate_weapon_usage_time,
    gameplay_enforce_weapon_guards,
    player_update,
    survival_progression_update,
)
from ..math_parity import f32, x87_pc24_mul
from ..owner_ref import OwnerRef
from ..perks import PerkId
from ..perks.effects import perks_update_effects
from ..perks.selection import perk_selection_open_choices
from ..player_damage import player_take_projectile_damage
from ..projectiles.runtime import PrimaryStepCtx, SecondaryStepCtx
from ..projectiles.types import ProjectileHit
from ..rng_caller_static import RngCallerStatic
from ..tutorial.timeline import tutorial_timeline_update
from ..typo.runtime import typo_mode_update
from .input import PlayerInput
from .input_frame import normalize_input_frame
from .mode_updates import (
    ModeState,
    QuestSpawnState,
    RushSpawnState,
    SurvivalSpawnState,
    quest_mode_update,
    rush_mode_update,
    survival_update,
)
from .presentation_step import (
    ProjectileDecalPostCtx,
    plan_hit_sfx,
    queue_projectile_decals_post_hit,
    queue_projectile_decals_pre_hit,
)
from .state_types import BonusPickupEvent, PlayerState
from .timing import ftol_ms_i32


class WorldEvents(msgspec.Struct):
    hits: list[ProjectileHit]
    deaths: tuple[CreatureDeath, ...]
    pickups: list[BonusPickupEvent]
    sfx: list[SfxRequest]
    secondary_hit_count: int = 0
    trigger_game_tune: bool = False
    hit_sfx: list[SfxRequest] = msgspec.field(default_factory=list)
    perk_menu_opened: bool = False
    # Active creatures after the simulation, before the world render culls finished corpses.
    creature_count_before_render: int = 0


class WorldStepRuntime(msgspec.Struct):
    world: WorldState
    dt: float
    fx_queue: FxQueue
    fx_queue_rotated: FxQueueRotated
    deaths: list[CreatureDeath]
    sfx: list[SfxRequest]
    trigger_game_tune: bool = False
    hit_sfx: list[SfxRequest] = msgspec.field(default_factory=list)

    def apply_player_damage(self, player_index: int, damage: float) -> None:
        idx = int(player_index)
        if not (0 <= idx < len(self.world.players)):
            return
        player_take_projectile_damage(self.world.state, self.world.players[idx], float(damage))

    def handle_creature_death(self, creature_index: int, *, keep_corpse: bool = True) -> None:
        """`creature_handle_death` for this frame, recording the death event."""

        self.deaths.append(
            self.world.creatures.handle_death(
                creature_index,
                state=self.world.state,
                players=self.world.players,
                rng=self.world.state.rng,
                dt=f32(self.dt),
                detail_preset=self.world.state.detail_preset,
                fx_queue=self.fx_queue,
                keep_corpse=keep_corpse,
            ),
        )

    def on_secondary_detonation_kill(self, creature_index: int) -> None:
        if self.world.creatures.entries[creature_index].hp > 0.0:
            return
        # Native detonation follow-up re-enters creature death handling but does
        # not run a second death-SFX random pick (`creature_apply_damage` only
        # does that on the original killing hit).
        self.handle_creature_death(creature_index)

    def begin_hit_presentation(self, hit: ProjectileHit) -> ProjectileDecalPostCtx:
        return queue_projectile_decals_pre_hit(
            state=self.world.state,
            players=self.world.players,
            fx_queue=self.fx_queue,
            hit=hit,
            rng=self.world.state.rng,
            detail_preset=self.world.state.detail_preset,
            violence_disabled=self.world.state.violence_disabled,
        )

    def finish_hit_presentation(self, hit: ProjectileHit, presentation: ProjectileDecalPostCtx) -> None:
        queue_projectile_decals_post_hit(
            state=self.world.state,
            fx_queue=self.fx_queue,
            post_ctx=msgspec.structs.replace(presentation, hit=hit),
            rng=self.world.state.rng,
            detail_preset=self.world.state.detail_preset,
        )
        hit_trigger, keys = plan_hit_sfx(
            [hit],
            game_mode=self.world.state.game_mode,
            game_tune_started=self.world.state.game_tune_started,
            rng=self.world.state.rng,
        )
        if hit_trigger:
            self.trigger_game_tune = True
            self.world.state.game_tune_started = True
        if keys:
            self.hit_sfx.extend(keys)

    def play_secondary_rocket_hit_audio(self, position: Vec2) -> None:
        # Native secondary-rocket hits run the same first-hit game-tune branch
        # as bullet hits: sfx_play_exclusive(music_track_extra_0) plus one
        # playlist rand outside rush, else the panned explosion sound.
        state = self.world.state
        if state.game_mode != GameMode.RUSH and not state.game_tune_started:
            self.trigger_game_tune = True
            state.game_tune_started = True
            _ = self.world.state.rng.rand_tagged(RngCallerStatic.SFX_PLAY_EXCLUSIVE_PLAYLIST_PICK)
            return
        self.hit_sfx.append(SfxRequest(SfxId.EXPLOSION_MEDIUM, position))

    def kill_creature_no_corpse(self, creature_index: int, owner: OwnerRef) -> None:
        creature = self.world.creatures.entries[creature_index]
        if creature.active:
            creature.last_hit_owner = owner
        self.handle_creature_death(creature_index, keep_corpse=False)

    def on_bubblegun_expiry_sfx(self, creature_index: int, sound_slot: int) -> None:
        idx = int(creature_index)
        if not (0 <= idx < len(self.world.creatures.entries)):
            return
        sfx_id = creature_death_sfx_for_slot(self.world.creatures.entries[idx].type_id, int(sound_slot))
        if sfx_id is not None:
            self.sfx.append(SfxRequest(sfx_id, self.world.creatures.entries[idx].pos))

    def build_events(
        self,
        *,
        hits: list[ProjectileHit],
        secondary_hit_count: int,
        pickups: list[BonusPickupEvent],
    ) -> WorldEvents:
        return WorldEvents(
            hits=hits,
            secondary_hit_count=int(secondary_hit_count),
            deaths=tuple(self.deaths),
            pickups=pickups,
            sfx=self.sfx,
            trigger_game_tune=bool(self.trigger_game_tune),
            hit_sfx=self.hit_sfx,
        )


class WorldState(msgspec.Struct):
    state: GameplayState
    players: list[PlayerState]
    creatures: CreaturePool

    @classmethod
    def build(
        cls,
        *,
        hardcore: bool,
        quest_fail_retry_count: int,
        preserve_bugs: bool = False,
    ) -> WorldState:
        state = GameplayState()
        state.hardcore = hardcore
        state.quest_fail_retry_count = int(quest_fail_retry_count)
        state.preserve_bugs = preserve_bugs
        players: list[PlayerState] = []
        creatures = CreaturePool()
        return cls(
            state=state,
            players=players,
            creatures=creatures,
        )

    def world_dt_after_perk_steps(self, dt: float) -> float:
        # Native `game_frame_update` scales frame_dt by 0.9 under Reflex Boosted.
        if dt > 0.0 and PerkId.REFLEX_BOOSTED in self.state.perks:
            return x87_pc24_mul(f32(dt), f32(0.9))
        return dt

    def step(
        self,
        dt: float,
        *,
        inputs: Sequence[PlayerInput] | None,
        fx_queue: FxQueue,
        fx_queue_rotated: FxQueueRotated,
        perk_progression_enabled: bool,
        mode_state: ModeState = None,
        elapsed_ms: float = 0.0,
        open_perk_menu: bool = False,
    ) -> WorldEvents:
        """Advance one frame; the caller has already applied the perk dt steps."""
        dt = float(dt)
        fx_queue.violence_disabled = self.state.violence_disabled
        frame_dt_ms = ftol_ms_i32(dt)
        inputs = normalize_input_frame(inputs, player_count=len(self.players))
        perks_update_effects(self.state, self.players, dt, creatures=self.creatures.entries, fx_queue=fx_queue)
        # `effects_update` runs early in the native frame loop, before creature/projectile updates.
        self.state.effects.update(dt, fx_queue=fx_queue)

        step_runtime = WorldStepRuntime(
            world=self,
            dt=float(dt),
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            deaths=[],
            sfx=[],
        )
        self.creatures.update(step_runtime)
        hits = self.state.projectiles.step(
            PrimaryStepCtx(step_runtime=step_runtime, dt=float(dt)),
        )
        secondary_hit_count = self.state.secondary_projectiles.step(
            SecondaryStepCtx(step_runtime=step_runtime, dt=float(dt)),
        )
        # Native updates the sprite pool before the particle loop, so sprites
        # spawned by particles only advance on the next tick.
        self.state.sprite_effects.update(dt)
        self.state.particles.update(dt, step_runtime=step_runtime)
        reload_active_any = any(bool(entry.reload_down) or bool(entry.reload_pressed) for entry in inputs)
        player_dt = float(dt)
        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player_dt = player_update(
                player,
                input_state,
                player_dt,
                step_runtime=step_runtime,
                reload_active_any=bool(reload_active_any),
            )
        dt = float(player_dt)
        # The mode updates read the elapsed run time from before this frame.
        match mode_state:
            case SurvivalSpawnState():
                survival_update(self, mode_state, elapsed_ms=elapsed_ms, dt_ms=float(frame_dt_ms))
            case RushSpawnState():
                rush_mode_update(self, mode_state, elapsed_ms=elapsed_ms, dt_ms=float(frame_dt_ms))
            case QuestSpawnState():
                quest_mode_update(self, mode_state, dt_ms=float(frame_dt_ms))
            case None if self.state.game_mode == GameMode.TYPO:
                typo_mode_update(self, elapsed_ms=elapsed_ms, dt_ms=float(frame_dt_ms))
        # The rest follows `gameplay_update_and_render` after the mode update:
        # bonus timers, camera, world render (Telekinetic pickups happen in
        # `bonus_render`), level-up, then `bonus_update`.
        self.state.highscore_score_xp = int(self.players[0].experience)
        # Native latches `time_scale_active` late (post mode update, pre bonus decrement); next-frame dt uses it.
        self.state.time_scale_active = float(self.state.bonuses.reflex_boost) > 0.0
        bonus_update_pre_pickup_timers(self.state, dt)
        gameplay_accumulate_weapon_usage_time(self.state, self.players, frame_dt_ms)
        gameplay_enforce_weapon_guards(self.state, self.players)
        camera_shake_update(self.state, dt)
        # `gameplay_render_world`: `creature_render_all` culls finished corpses, then `bonus_render`
        # makes the Telekinetic pickups.
        creature_count_before_render = len(self.creatures.iter_active())
        self.creatures.finalize_post_render_lifecycle()
        pickups = bonus_telekinetic_update(
            self.state,
            self.players,
            dt,
            creatures=self.creatures.entries,
            detail_preset=self.state.detail_preset,
            step_runtime=step_runtime,
        )
        if self.state.game_mode == GameMode.TUTORIAL:
            tutorial_timeline_update(self, dt_ms=frame_dt_ms)
        # The death check, then the level-up check. XP awarded by `bonus_update` kills
        # (e.g. freeze cleanup) levels next tick.
        if perk_progression_enabled:
            survival_progression_update(self.state, self.players)
        # A perk-menu request opens here, mid-frame: native generates the choices
        # after this frame's simulation and before `bonus_update`, and only while
        # a perk is pending and someone is alive.
        perk_menu_opened = (
            open_perk_menu
            and perk_progression_enabled
            and self.state.perk_selection.pending_count > 0
            and any(player.health > 0.0 for player in self.players)
        )
        if perk_menu_opened:
            perk_selection_open_choices(self.state, self.players, game_mode=self.state.game_mode)
        pickups += bonus_update(
            self.state,
            self.players,
            dt,
            creatures=self.creatures.entries,
            detail_preset=self.state.detail_preset,
            step_runtime=step_runtime,
        )
        if self.state.sfx_queue:
            step_runtime.sfx.extend(self.state.sfx_queue)
            self.state.sfx_queue.clear()
        events = step_runtime.build_events(
            hits=hits,
            secondary_hit_count=int(secondary_hit_count),
            pickups=pickups,
        )
        events.perk_menu_opened = perk_menu_opened
        events.creature_count_before_render = creature_count_before_render
        return events
