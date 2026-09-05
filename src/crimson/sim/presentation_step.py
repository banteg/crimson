from __future__ import annotations

import math
from collections.abc import Sequence

import msgspec

from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx_map import SfxId

from ..bonuses.fire_bullets import LargeHitDecalRuntime
from ..bonuses.freeze import freeze_bonus_active
from ..effects import FxQueue
from ..features.presentation import queue_projectile_large_streak_decal
from ..game_modes import GameMode
from ..perks import PerkId
from ..perks.helpers import perk_active
from ..projectiles.types import ProjectileHit, ProjectileTemplateId
from ..rng_caller_static import RngCallerStatic
from ..weapons import WEAPON_BY_ID, WeaponId, weapon_entry_for_projectile_type_id
from .state_types import BonusPickupEvent, GameplayState, PlayerState
from .terrain_fx import TerrainFxBatch
from .world_defs import BEAM_TYPES

_BULLET_HIT_SFX = (
    SfxId.BULLET_HIT_01,
    SfxId.BULLET_HIT_02,
    SfxId.BULLET_HIT_03,
    SfxId.BULLET_HIT_04,
    SfxId.BULLET_HIT_05,
    SfxId.BULLET_HIT_06,
)


class DeterministicPresentationPlan(msgspec.Struct, frozen=True):
    """Deterministic native-parity presentation effects emitted by one sim tick."""

    trigger_game_tune: bool = False
    sfx: tuple[SfxId, ...] = ()
    terrain_fx: TerrainFxBatch = TerrainFxBatch()
    post_apply_sfx: tuple[SfxId, ...] = ()
    play_quest_completion_music: bool = False


class PresentationPlanRuntime(msgspec.Struct):
    def trigger_game_tune(self) -> str | None:
        return None

    def play_sfx(self, sfx: SfxId) -> None:
        _ = sfx


def plan_player_audio_sfx(
    player: PlayerState,
    *,
    prev_shot_seq: int,
    prev_reload_active: bool,
    prev_reload_timer: float,
) -> list[SfxId]:
    sfx: list[SfxId] = []

    weapon = WEAPON_BY_ID[player.weapon.weapon_id]

    if int(player.shot_seq) > int(prev_shot_seq):
        if float(player.fire_bullets_timer) > 0.0:
            fire_bullets = WEAPON_BY_ID[WeaponId.FIRE_BULLETS]
            plasma_minigun = WEAPON_BY_ID[WeaponId.PLASMA_MINIGUN]
            sfx.append(fire_bullets.fire_sound)
            sfx.append(plasma_minigun.fire_sound)
        else:
            sfx.append(weapon.fire_sound)

    reload_active = player.weapon.reload_active
    reload_timer = float(player.weapon.reload_timer)
    reload_started = (not prev_reload_active and reload_active) or (reload_timer > prev_reload_timer + 1e-6)
    if reload_started:
        sfx.append(weapon.reload_sound)

    return sfx


def _hit_sfx_for_type(
    type_id: int,
    *,
    beam_types: frozenset[int],
    rng: CrandLike,
) -> SfxId:
    _ = beam_types
    ammo_class = weapon_entry_for_projectile_type_id(ProjectileTemplateId(type_id)).ammo_class
    if ammo_class == 4:
        return SfxId.SHOCK_HIT_01
    return _BULLET_HIT_SFX[rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX) % len(_BULLET_HIT_SFX)]


def plan_hit_sfx(
    hits: list[ProjectileHit],
    *,
    game_mode: GameMode,
    demo_mode_active: bool,
    game_tune_started: bool,
    rng: CrandLike,
    beam_types: frozenset[int] = BEAM_TYPES,
) -> tuple[bool, list[SfxId]]:
    if not hits:
        return False, []

    trigger_game_tune = False
    local_game_tune_started = bool(game_tune_started)
    # Native draws a hit-sound rand and plays the panned sample for every hit,
    # uncapped; the per-hit world-step path already matches this.
    sfx: list[SfxId] = []
    for idx in range(len(hits)):
        if (not demo_mode_active) and game_mode != GameMode.RUSH and (not local_game_tune_started):
            # Mirrors `projectile_update`: first eligible hit calls
            # `sfx_play_exclusive(music_track_extra_0)` and skips the panned
            # bullet/shock hit sound for that same hit. Native
            # `sfx_play_exclusive` also performs one RNG draw to pick the
            # playlist entry, so consume one draw here for stream parity.
            trigger_game_tune = True
            local_game_tune_started = True
            _ = rng.rand_tagged(RngCallerStatic.SFX_PLAY_EXCLUSIVE_PLAYLIST_PICK)
            continue
        type_id = int(hits[idx].type_id)
        sfx.append(_hit_sfx_for_type(type_id, beam_types=beam_types, rng=rng))
    return trigger_game_tune, sfx


class ProjectileDecalPostCtx(msgspec.Struct, frozen=True):
    hit: ProjectileHit
    base_angle: float
    type_id: int
    freeze_active: bool
    large_hit_decal_runtime: LargeHitDecalRuntime | None = None


class _ProjectileFreezeShardRuntime(LargeHitDecalRuntime):
    state: GameplayState
    rng: CrandLike
    detail_preset: int

    def spawn_freeze_shard(self, pos: Vec2, angle: float) -> None:
        self.state.effects.spawn_freeze_shard(
            pos=pos,
            angle=float(angle),
            rng=self.rng,
            detail_preset=int(self.detail_preset),
        )


def queue_projectile_decals(
    *,
    state: GameplayState,
    players: Sequence[PlayerState],
    fx_queue: FxQueue,
    hits: list[ProjectileHit],
    rng: CrandLike,
    detail_preset: int,
    violence_disabled: int,
) -> None:
    for hit in hits:
        post_ctx = queue_projectile_decals_pre_hit(
            state=state,
            players=players,
            fx_queue=fx_queue,
            hit=hit,
            rng=rng,
            detail_preset=detail_preset,
            violence_disabled=violence_disabled,
        )
        queue_projectile_decals_post_hit(
            fx_queue=fx_queue,
            post_ctx=post_ctx,
            rng=rng,
        )


def queue_projectile_decals_pre_hit(
    *,
    state: GameplayState,
    players: Sequence[PlayerState],
    fx_queue: FxQueue,
    hit: ProjectileHit,
    rng: CrandLike,
    detail_preset: int,
    violence_disabled: int,
) -> ProjectileDecalPostCtx:
    freeze_active = freeze_bonus_active(state=state)
    bloody = bool(players) and perk_active(players[0], PerkId.BLOODY_MESS_QUICK_LEARNER)
    large_hit_decal_runtime: LargeHitDecalRuntime | None = None
    if freeze_active:
        large_hit_decal_runtime = _ProjectileFreezeShardRuntime(
            state=state,
            rng=rng,
            detail_preset=int(detail_preset),
        )

    type_id = hit.type_id

    base_angle = (hit.hit - hit.origin).to_angle()

    if type_id == ProjectileTemplateId.BLADE_GUN:
        for _ in range(8):
            state.effects.spawn_blood_splatter(
                pos=hit.hit,
                angle=float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_BLADE_GUN_SPLATTER_ANGLE) & 0xFF)
                * 0.024543693,
                age=0.0,
                rng=rng,
                detail_preset=detail_preset,
                violence_disabled=violence_disabled,
            )

    # Native `projectile_update` spawns blood splatter before terrain decals.
    # The whole splatter block (including its spread / reverse-gate rand draws)
    # sits inside `if (config_violence_disabled == '\0')`; the bloody-mess decal
    # loop below runs regardless of the violence setting.
    if bloody:
        if not violence_disabled:
            for _ in range(8):
                spread = (
                    float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_SPREAD) & 0x1F) - 16.0
                ) * 0.0625
                state.effects.spawn_blood_splatter(
                    pos=hit.hit,
                    angle=base_angle + spread,
                    age=0.0,
                    rng=rng,
                    detail_preset=detail_preset,
                    violence_disabled=violence_disabled,
                )
            state.effects.spawn_blood_splatter(
                pos=hit.hit,
                angle=base_angle + math.pi,
                age=0.0,
                rng=rng,
                detail_preset=detail_preset,
                violence_disabled=violence_disabled,
            )

        lo = -30
        hi = 30
        while lo > -60:
            span = hi - lo
            for dx_caller, dy_caller in (
                (
                    RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DX_1,
                    RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DY_1,
                ),
                (
                    RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DX_2,
                    RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DY_2,
                ),
            ):
                dx = float(rng.rand_tagged(dx_caller) % span + lo)
                dy = float(rng.rand_tagged(dy_caller) % span + lo)
                fx_queue.add_random(
                    pos=hit.target + Vec2(dx, dy),
                    rng=rng,
                )
            lo -= 10
            hi += 10
    elif not freeze_active and not violence_disabled:
        for _ in range(2):
            state.effects.spawn_blood_splatter(
                pos=hit.hit,
                angle=base_angle,
                age=0.0,
                rng=rng,
                detail_preset=detail_preset,
                violence_disabled=violence_disabled,
            )
            if (rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_DEFAULT_REVERSE_SPLATTER_GATE) & 7) == 2:
                state.effects.spawn_blood_splatter(
                    pos=hit.hit,
                    angle=base_angle + math.pi,
                    age=0.0,
                    rng=rng,
                    detail_preset=detail_preset,
                    violence_disabled=violence_disabled,
                )

    return ProjectileDecalPostCtx(
        hit=hit,
        base_angle=float(base_angle),
        type_id=int(type_id),
        freeze_active=bool(freeze_active),
        large_hit_decal_runtime=large_hit_decal_runtime,
    )


def queue_projectile_decals_post_hit(
    *,
    fx_queue: FxQueue,
    post_ctx: ProjectileDecalPostCtx,
    rng: CrandLike,
) -> None:
    hit = post_ctx.hit
    base_angle = float(post_ctx.base_angle)

    # Native consumes one extra `crt_rand()` per creature hit before the
    # post-hit terrain decal burst branch.
    rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_POST_HIT_DECAL_BURN)

    hook_handled = queue_projectile_large_streak_decal(
        hit=hit,
        base_angle=float(base_angle),
        fx_queue=fx_queue,
        rng=rng,
        freeze_origin=hit.hit if bool(post_ctx.freeze_active) else None,
        runtime=post_ctx.large_hit_decal_runtime,
    )

    if bool(hook_handled):
        return

    if bool(post_ctx.freeze_active):
        # Native: with Freeze active, default hits spawn one freeze shard here,
        # after the burn draw, instead of the streak decal loop.
        runtime = post_ctx.large_hit_decal_runtime
        if runtime is not None:
            shard_angle = (
                base_angle
                + float(
                    rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_DEFAULT_FREEZE_SHARD_ANGLE) % 100,
                )
                * 0.01
            )
            runtime.spawn_freeze_shard(hit.hit, float(shard_angle))
        return

    for _ in range(3):
        spread = float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_DECAL_SPREAD) % 20 - 10) * 0.1
        angle = base_angle + spread
        direction = Vec2.from_angle(angle) * 20.0
        fx_queue.add_random(pos=hit.target, rng=rng)
        fx_queue.add_random(
            pos=hit.target + direction * 1.5,
            rng=rng,
        )
        fx_queue.add_random(
            pos=hit.target + direction * 2.0,
            rng=rng,
        )
        fx_queue.add_random(
            pos=hit.target + direction * 2.5,
            rng=rng,
        )


def plan_world_presentation_step(
    *,
    state: GameplayState,
    players: Sequence[PlayerState],
    fx_queue: FxQueue,
    hits: list[ProjectileHit],
    pickups: list[BonusPickupEvent],
    event_sfx: list[SfxId],
    prev_audio: Sequence[tuple[int, bool, float]],
    prev_perk_pending: int,
    game_mode: GameMode,
    demo_mode_active: bool,
    perk_progression_enabled: bool,
    rng: CrandLike,
    detail_preset: int,
    violence_disabled: int,
    game_tune_started: bool,
    trigger_game_tune: bool | None = None,
    hit_sfx: Sequence[SfxId] | None = None,
) -> DeterministicPresentationPlan:
    sfx: list[SfxId] = []
    play_game_tune = False
    if perk_progression_enabled and int(state.perk_selection.pending_count) > int(prev_perk_pending):
        sfx.append(SfxId.UI_LEVELUP)
    if trigger_game_tune is None and hit_sfx is None:
        if hits:
            queue_projectile_decals(
                state=state,
                players=players,
                fx_queue=fx_queue,
                hits=hits,
                rng=rng,
                detail_preset=int(detail_preset),
                violence_disabled=int(violence_disabled),
            )
            if freeze_bonus_active(state=state):
                if (not bool(demo_mode_active)) and game_mode != GameMode.RUSH and (not bool(game_tune_started)):
                    play_game_tune = True
            else:
                play_game_tune, planned_hit_sfx = plan_hit_sfx(
                    hits,
                    game_mode=game_mode,
                    demo_mode_active=bool(demo_mode_active),
                    game_tune_started=bool(game_tune_started),
                    rng=rng,
                )
                sfx.extend(planned_hit_sfx)
    else:
        if trigger_game_tune is not None:
            play_game_tune = bool(trigger_game_tune)
        if hit_sfx is not None:
            sfx.extend(hit_sfx)
    for idx, player in enumerate(players):
        if idx >= len(prev_audio):
            continue
        prev_shot_seq, prev_reload_active, prev_reload_timer = prev_audio[idx]
        sfx.extend(
            plan_player_audio_sfx(
                player,
                prev_shot_seq=int(prev_shot_seq),
                prev_reload_active=bool(prev_reload_active),
                prev_reload_timer=float(prev_reload_timer),
            ),
        )
    if pickups:
        sfx.extend(SfxId.UI_BONUS for _ in pickups)
    sfx.extend(event_sfx[:4])
    return DeterministicPresentationPlan(trigger_game_tune=play_game_tune, sfx=tuple(sfx))


def apply_presentation_plan(
    *,
    plan: DeterministicPresentationPlan,
    runtime: PresentationPlanRuntime | None,
    apply_audio: bool = True,
) -> None:
    if not bool(apply_audio) or runtime is None:
        return
    if bool(plan.trigger_game_tune):
        runtime.trigger_game_tune()
    for sfx in plan.sfx:
        runtime.play_sfx(sfx)
