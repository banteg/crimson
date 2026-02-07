from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Callable, Sequence

from grim.geom import Vec2

from ..creatures.runtime import CreatureDeath
from ..creatures.spawn import CreatureTypeId
from ..effects import FxQueue
from ..features.bonuses.freeze import freeze_bonus_active
from ..features.presentation import ProjectileDecalCtx, run_projectile_decal_hooks
from ..game_modes import GameMode
from ..gameplay import BonusPickupEvent, GameplayState, PlayerState, perk_active
from ..perks import PerkId
from ..projectiles import ProjectileHit
from ..weapon_sfx import resolve_weapon_sfx_ref
from ..weapons import WEAPON_BY_ID, WeaponId
from .world_defs import BEAM_TYPES, ION_TYPES

_MAX_HIT_SFX_PER_FRAME = 4
_MAX_DEATH_SFX_PER_FRAME = 3

_BULLET_HIT_SFX = (
    "sfx_bullet_hit_01",
    "sfx_bullet_hit_02",
    "sfx_bullet_hit_03",
    "sfx_bullet_hit_04",
    "sfx_bullet_hit_05",
    "sfx_bullet_hit_06",
)

_CREATURE_DEATH_SFX: dict[CreatureTypeId, tuple[str, ...]] = {
    CreatureTypeId.ZOMBIE: (
        "sfx_zombie_die_01",
        "sfx_zombie_die_02",
        "sfx_zombie_die_03",
        "sfx_zombie_die_04",
    ),
    CreatureTypeId.LIZARD: (
        "sfx_lizard_die_01",
        "sfx_lizard_die_02",
        "sfx_lizard_die_03",
        "sfx_lizard_die_04",
    ),
    CreatureTypeId.ALIEN: (
        "sfx_alien_die_01",
        "sfx_alien_die_02",
        "sfx_alien_die_03",
        "sfx_alien_die_04",
    ),
    CreatureTypeId.SPIDER_SP1: (
        "sfx_spider_die_01",
        "sfx_spider_die_02",
        "sfx_spider_die_03",
        "sfx_spider_die_04",
    ),
    CreatureTypeId.SPIDER_SP2: (
        "sfx_spider_die_01",
        "sfx_spider_die_02",
        "sfx_spider_die_03",
        "sfx_spider_die_04",
    ),
    CreatureTypeId.TROOPER: (
        "sfx_trooper_die_01",
        "sfx_trooper_die_02",
        "sfx_trooper_die_03",
        "sfx_trooper_die_04",
    ),
}


@dataclass(slots=True)
class PresentationStepCommands:
    trigger_game_tune: bool = False
    sfx_keys: list[str] = field(default_factory=list)


def plan_player_audio_sfx(
    player: object,
    *,
    prev_shot_seq: int,
    prev_reload_active: bool,
    prev_reload_timer: float,
) -> list[str]:
    keys: list[str] = []

    weapon = WEAPON_BY_ID.get(int(getattr(player, "weapon_id", 0)))
    if weapon is None:
        return keys

    if int(getattr(player, "shot_seq", 0)) > int(prev_shot_seq):
        if float(getattr(player, "fire_bullets_timer", 0.0)) > 0.0:
            fire_bullets = WEAPON_BY_ID.get(int(WeaponId.FIRE_BULLETS))
            plasma_minigun = WEAPON_BY_ID.get(int(WeaponId.PLASMA_MINIGUN))
            if fire_bullets is not None:
                key = resolve_weapon_sfx_ref(fire_bullets.fire_sound)
                if key is not None:
                    keys.append(key)
            if plasma_minigun is not None:
                key = resolve_weapon_sfx_ref(plasma_minigun.fire_sound)
                if key is not None:
                    keys.append(key)
        else:
            key = resolve_weapon_sfx_ref(weapon.fire_sound)
            if key is not None:
                keys.append(key)

    reload_active = bool(getattr(player, "reload_active", False))
    reload_timer = float(getattr(player, "reload_timer", 0.0))
    reload_started = (not prev_reload_active and reload_active) or (reload_timer > prev_reload_timer + 1e-6)
    if reload_started:
        key = resolve_weapon_sfx_ref(weapon.reload_sound)
        if key is not None:
            keys.append(key)

    return keys


def _rand_choice(rand: Callable[[], int], options: tuple[str, ...]) -> str | None:
    if not options:
        return None
    idx = int(rand()) % len(options)
    return options[idx]


def _hit_sfx_for_type(
    type_id: int,
    *,
    beam_types: frozenset[int],
    rand: Callable[[], int],
) -> str | None:
    _ = beam_types
    weapon = WEAPON_BY_ID.get(int(type_id))
    ammo_class = weapon.ammo_class if weapon is not None else None
    if ammo_class == 4:
        return "sfx_shock_hit_01"
    return _rand_choice(rand, _BULLET_HIT_SFX)


def plan_hit_sfx_keys(
    hits: list[ProjectileHit],
    *,
    game_mode: int,
    demo_mode_active: bool,
    game_tune_started: bool,
    rand: Callable[[], int],
    beam_types: frozenset[int] = BEAM_TYPES,
) -> tuple[bool, list[str]]:
    if not hits:
        return False, []

    trigger_game_tune = False
    start_idx = 0
    if (not demo_mode_active) and int(game_mode) != int(GameMode.RUSH) and (not game_tune_started):
        trigger_game_tune = True
        start_idx = 1

    end = min(len(hits), start_idx + _MAX_HIT_SFX_PER_FRAME)
    keys: list[str] = []
    for idx in range(start_idx, end):
        type_id = int(hits[idx].type_id)
        key = _hit_sfx_for_type(type_id, beam_types=beam_types, rand=rand)
        if key is not None:
            keys.append(key)
    return trigger_game_tune, keys


def plan_death_sfx_keys(
    deaths: Sequence[CreatureDeath] | tuple[object, ...],
    *,
    rand: Callable[[], int],
) -> list[str]:
    keys: list[str] = []
    if not deaths:
        return keys

    for idx in range(min(len(deaths), _MAX_DEATH_SFX_PER_FRAME)):
        death = deaths[idx]
        type_id = getattr(death, "type_id", None)
        if type_id is None:
            continue
        try:
            creature_type = CreatureTypeId(int(type_id))
        except ValueError:
            continue
        options = _CREATURE_DEATH_SFX.get(creature_type)
        if options:
            key = _rand_choice(rand, options)
            if key is not None:
                keys.append(key)
    return keys


def queue_projectile_decals(
    *,
    state: GameplayState,
    players: Sequence[PlayerState],
    fx_queue: FxQueue,
    hits: list[ProjectileHit],
    rand: Callable[[], int],
    detail_preset: int,
    fx_toggle: int,
) -> None:
    freeze_active = freeze_bonus_active(state=state)
    bloody = bool(players) and perk_active(players[0], PerkId.BLOODY_MESS_QUICK_LEARNER)

    for hit in hits:
        type_id = int(hit.type_id)

        base_angle = (hit.hit - hit.origin).to_angle()

        hook_handled = run_projectile_decal_hooks(
            ProjectileDecalCtx(
                hit=hit,
                base_angle=float(base_angle),
                fx_queue=fx_queue,
                rand=rand,
            )
        )

        # Native `projectile_update` spawns blood splatter before terrain decals.
        if bloody:
            for _ in range(8):
                spread = float((int(rand()) & 0x1F) - 0x10) * 0.0625
                state.effects.spawn_blood_splatter(
                    pos=hit.hit,
                    angle=base_angle + spread,
                    age=0.0,
                    rand=rand,
                    detail_preset=detail_preset,
                    fx_toggle=fx_toggle,
                )
            state.effects.spawn_blood_splatter(
                pos=hit.hit,
                angle=base_angle + math.pi,
                age=0.0,
                rand=rand,
                detail_preset=detail_preset,
                fx_toggle=fx_toggle,
            )

            lo = -30
            hi = 30
            while lo > -60:
                span = hi - lo
                for _ in range(2):
                    dx = float(int(rand()) % span + lo)
                    dy = float(int(rand()) % span + lo)
                    fx_queue.add_random(
                        pos=hit.target + Vec2(dx, dy),
                        rand=rand,
                    )
                lo -= 10
                hi += 10
        elif not freeze_active:
            for _ in range(2):
                state.effects.spawn_blood_splatter(
                    pos=hit.hit,
                    angle=base_angle,
                    age=0.0,
                    rand=rand,
                    detail_preset=detail_preset,
                    fx_toggle=fx_toggle,
                )
                if (int(rand()) & 7) == 2:
                    state.effects.spawn_blood_splatter(
                        pos=hit.hit,
                        angle=base_angle + math.pi,
                        age=0.0,
                        rand=rand,
                        detail_preset=detail_preset,
                        fx_toggle=fx_toggle,
                    )

        # Native consumes one extra `crt_rand()` per creature hit before the
        # post-hit terrain decal burst branch.
        rand()

        if hook_handled or type_id in ION_TYPES or freeze_active:
            continue

        for _ in range(3):
            spread = float(int(rand()) % 0x14 - 10) * 0.1
            angle = base_angle + spread
            direction = Vec2.from_angle(angle) * 20.0
            fx_queue.add_random(pos=hit.target, rand=rand)
            fx_queue.add_random(
                pos=hit.target + direction * 1.5,
                rand=rand,
            )
            fx_queue.add_random(
                pos=hit.target + direction * 2.0,
                rand=rand,
            )
            fx_queue.add_random(
                pos=hit.target + direction * 2.5,
                rand=rand,
            )


def apply_world_presentation_step(
    *,
    state: GameplayState,
    players: Sequence[PlayerState],
    fx_queue: FxQueue,
    hits: list[ProjectileHit],
    deaths: tuple[CreatureDeath, ...],
    pickups: list[BonusPickupEvent],
    event_sfx: list[str],
    prev_audio: Sequence[tuple[int, bool, float]],
    prev_perk_pending: int,
    game_mode: int,
    demo_mode_active: bool,
    perk_progression_enabled: bool,
    rand: Callable[[], int],
    rand_for: Callable[[str], Callable[[], int]] | None = None,
    detail_preset: int,
    fx_toggle: int,
    game_tune_started: bool,
    trigger_game_tune: bool | None = None,
    hit_sfx: Sequence[str] | None = None,
) -> PresentationStepCommands:
    commands = PresentationStepCommands()
    if rand_for is None:
        def rand_for(_label: str) -> Callable[[], int]:
            return rand

    if perk_progression_enabled and int(state.perk_selection.pending_count) > int(prev_perk_pending):
        commands.sfx_keys.append("sfx_ui_levelup")

    if trigger_game_tune is None and hit_sfx is None:
        if hits:
            queue_projectile_decals(
                state=state,
                players=players,
                fx_queue=fx_queue,
                hits=hits,
                rand=rand_for("projectile_decals"),
                detail_preset=int(detail_preset),
                fx_toggle=int(fx_toggle),
            )
            commands.trigger_game_tune, planned_hit_sfx = plan_hit_sfx_keys(
                hits,
                game_mode=int(game_mode),
                demo_mode_active=bool(demo_mode_active),
                game_tune_started=bool(game_tune_started),
                rand=rand_for("hit_sfx"),
            )
            commands.sfx_keys.extend(planned_hit_sfx)
    else:
        if trigger_game_tune is not None:
            commands.trigger_game_tune = bool(trigger_game_tune)
        if hit_sfx is not None:
            commands.sfx_keys.extend(str(key) for key in hit_sfx)

    for idx, player in enumerate(players):
        if idx >= len(prev_audio):
            continue
        prev_shot_seq, prev_reload_active, prev_reload_timer = prev_audio[idx]
        commands.sfx_keys.extend(
            plan_player_audio_sfx(
                player,
                prev_shot_seq=int(prev_shot_seq),
                prev_reload_active=bool(prev_reload_active),
                prev_reload_timer=float(prev_reload_timer),
            )
        )

    if deaths:
        commands.sfx_keys.extend(plan_death_sfx_keys(deaths, rand=rand_for("death_sfx")))

    if pickups:
        for _ in pickups:
            commands.sfx_keys.append("sfx_ui_bonus")

    commands.sfx_keys.extend(str(key) for key in event_sfx[:4])
    return commands
