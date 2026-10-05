from __future__ import annotations

import math
from collections.abc import Sequence

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp01
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..bonuses.ids import BonusId
from ..bonuses.update import bonus_telekinetic_update
from ..camera import camera_shake_update
from ..creatures.spawn import CreatureTypeId
from ..effects import FxQueue, FxQueueRotated
from ..gameplay import (
    gameplay_accumulate_weapon_usage_time,
    gameplay_enforce_weapon_guards,
    player_weapon_popup_timer_update,
)
from ..math_parity import f32, x87_pc24_add, x87_pc24_cos_mul, x87_pc24_mul
from ..perks.effects import perks_update_effects
from ..rng_caller_static import RngCallerStatic
from ..sim.commands import TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from ..sim.state_types import TERRAIN_SIZE
from ..sim.timing import FrameTiming
from ..sim.world_state import WorldEvents, WorldState, WorldStepRuntime
from ..weapons import WeaponId
from .player import typo_player_update
from .spawns import creature_spawn_tinted

type TypoCommand = TypoCharCommand | TypoBackspaceCommand | TypoSubmitCommand

# `typo_gameplay_update_and_render`: Reflex Boost slows Typ-o by a flat factor.
TYPO_TIME_SCALE_FACTOR = f32(0.3)


class TypoFireRequest(msgspec.Struct):
    """The frame's Enter results, the locals `typo_gameplay_update_and_render` hands `typo_player_update`."""

    fire: bool = False
    reload: bool = False


def _typeclick_sfx(world: WorldState, *, caller: RngCallerStatic) -> SfxId:
    if (world.state.rng.rand_tagged(caller) & 1) == 0:
        return SfxId.UI_TYPECLICK_01
    return SfxId.UI_TYPECLICK_02


def typo_input_update(world: WorldState, commands: Sequence[TypoCommand]) -> TypoFireRequest:
    """The typing block that opens `typo_gameplay_update_and_render`: Enter, then the polled key.

    Live play queues Enter before the frame's one key, as native reads them.
    """

    typo = world.state.typo
    typing = typo.typing
    request = TypoFireRequest()
    for command in commands:
        if int(command.player_index) != 0:
            raise RuntimeError("Typ-o Shooter commands are single-player only")
        match command:
            case TypoSubmitCommand():
                if not typing.text:
                    continue
                world.state.sfx_queue.append(SfxRequest(SfxId.UI_TYPEENTER, None))
                active_mask = [entry.active for entry in world.creatures.entries]
                target_idx = typo.names.find_by_name(typing.text, active_mask=active_mask)
                entered = typing.submit(matched=target_idx is not None)
                if target_idx is not None:
                    request.fire = True
                    typo.target_world = world.creatures.entries[target_idx].pos
                elif entered == "reload":
                    request.reload = True
            case TypoBackspaceCommand():
                world.state.sfx_queue.append(
                    SfxRequest(_typeclick_sfx(world, caller=RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_BACKSPACE), None),
                )
                typing.backspace()
            case TypoCharCommand(ch=ch):
                typing.push_char(str(ch))
                world.state.sfx_queue.append(
                    SfxRequest(_typeclick_sfx(world, caller=RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_CHAR), None),
                )
    return request


def typo_spawn_update(world: WorldState, *, elapsed_ms: int, dt_ms: int) -> None:
    """The spawn loop of `typo_gameplay_update_and_render`: a spider and an alien from the sides per cooldown."""

    typo = world.state.typo
    typo.spawn_cooldown_ms -= dt_ms * len(world.players)
    while typo.spawn_cooldown_ms < 0:
        typo.spawn_cooldown_ms = max(100, typo.spawn_cooldown_ms + 3500 - elapsed_ms // 800)
        # 0x00445af4..0x00445c15: float literals at PC24; `fsin`/`fcos` stay wide until the next op rounds.
        tint_t = float(elapsed_ms + 1)
        tint = RGBA(
            clamp01(x87_pc24_add(x87_pc24_mul(tint_t, f32(0.00000833333343)), f32(0.3))),
            clamp01(x87_pc24_add(x87_pc24_mul(tint_t, 10000.0), f32(0.3))),
            clamp01(x87_pc24_add(math.sin(x87_pc24_mul(tint_t, f32(0.000100000005))), f32(0.3))),
            1.0,
        )
        y = x87_pc24_add(x87_pc24_cos_mul(x87_pc24_mul(float(elapsed_ms), f32(0.001)), 256.0), TERRAIN_SIZE * 0.5)
        for pos, type_id in (
            (Vec2(x87_pc24_add(TERRAIN_SIZE, 64.0), y), CreatureTypeId.SPIDER_SP2),
            (Vec2(-64.0, y), CreatureTypeId.ALIEN),
        ):
            # A full pool hands back the phantom slot, which native names too, one past its name table.
            creature_idx = creature_spawn_tinted(world, pos, tint, type_id)
            typo.names.assign_random(
                creature_idx,
                world.state.rng,
                score_xp=world.state.highscore_score_xp,
                active_mask=[entry.active for entry in world.creatures.entries],
                dictionary_words=typo.dictionary_words,
                highscore_names=typo.highscore_names,
            )


def typo_gameplay_update(
    world: WorldState,
    *,
    commands: Sequence[TypoCommand],
    timing: FrameTiming,
    fx_queue: FxQueue,
    fx_queue_rotated: FxQueueRotated,
    elapsed_ms: float,
) -> WorldEvents:
    """The simulation of `typo_gameplay_update_and_render` (0x004457c0), in native order.

    Typ-o never runs `player_update`, `bonus_update` or the level-up check. `timing` carries the
    frame's dt before (`dt`) and after (`dt_sim`) the Reflex Boost scaling; perks and the HUD see the
    unscaled one. The mode's elapsed time advances with the session.
    """

    state = world.state
    players = world.players
    fx_queue.violence_disabled = state.violence_disabled
    fire_request = typo_input_update(world, commands)

    perks_update_effects(state, players, timing.dt, creatures=world.creatures.entries, fx_queue=fx_queue)
    dt = timing.dt_sim
    frame_dt_ms = timing.dt_sim_ms_i32
    state.effects.update(dt, fx_queue=fx_queue)

    step_runtime = WorldStepRuntime(
        world=world,
        dt=dt,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        deaths=[],
        sfx=[],
    )
    world.creatures.update(step_runtime)
    hits, secondary_hit_count = world.projectile_update(step_runtime)
    for player in players:
        typo_player_update(
            state,
            players,
            player,
            state.typo.target_world,
            fire_requested=fire_request.fire,
            reload_requested=fire_request.reload,
            dt=dt,
        )

    # Native stomps player 0 to the shotgun with 30 ammo, without `weapon_assign_player`:
    # the reset pistol's clip stays.
    players[0].weapon.weapon_id = WeaponId.SHOTGUN
    players[0].weapon.ammo = 30.0
    typo_spawn_update(world, elapsed_ms=int(elapsed_ms), dt_ms=frame_dt_ms)

    state.highscore_score_xp = int(players[0].experience)
    state.bonuses.weapon_power_up = 0.0
    state.bonuses.reflex_boost = 0.0
    state.time_scale_active = False
    gameplay_accumulate_weapon_usage_time(state, players, frame_dt_ms)

    camera_shake_update(state, dt)
    # `gameplay_render_world`: the weapon guards, `creature_render_all` culls finished corpses,
    # then `bonus_render` makes the Telekinetic pickups.
    gameplay_enforce_weapon_guards(state, players)
    creature_count_before_render = len(world.creatures.iter_active())
    world.creatures.finalize_post_render_lifecycle()
    pickups = bonus_telekinetic_update(
        state,
        players,
        dt,
        creatures=world.creatures.entries,
        detail_preset=state.detail_preset,
        step_runtime=step_runtime,
    )
    for entry in state.bonus_pool.entries:
        entry.bonus_id = BonusId.UNUSED
    # `hud_update_and_render`, after the frame dt is restored.
    for player in players:
        player_weapon_popup_timer_update(player, timing.dt)

    step_runtime.sfx.extend(state.sfx_queue)
    state.sfx_queue.clear()
    events = step_runtime.build_events(hits=hits, secondary_hit_count=secondary_hit_count, pickups=pickups)
    events.creature_count_before_render = creature_count_before_render
    return events
