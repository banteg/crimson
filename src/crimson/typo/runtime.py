from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp01
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..creatures.spawn import CreatureTypeId
from ..math_parity import f32, x87_pc24_add, x87_pc24_cos_mul, x87_pc24_mul
from ..rng_caller_static import RngCallerStatic
from ..sim.commands import TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from ..sim.input import PlayerInput
from ..sim.state_types import TERRAIN_SIZE
from .player import TYPO_WEAPON_ID, enforce_typo_player_frame
from .spawns import creature_spawn_tinted

if TYPE_CHECKING:
    from ..sim.world_state import WorldState


def _require_single_player_typo(command) -> None:
    if int(command.player_index) != 0:
        raise RuntimeError("Typ-o Shooter commands are single-player only")


def _typeclick_sfx(world: WorldState, *, caller: RngCallerStatic) -> SfxId:
    if (world.state.rng.rand_tagged(caller) & 1) == 0:
        return SfxId.UI_TYPECLICK_01
    return SfxId.UI_TYPECLICK_02


def apply_typo_command(world: WorldState, command: TypoCharCommand | TypoBackspaceCommand | TypoSubmitCommand) -> None:
    _require_single_player_typo(command)
    typo = world.state.typo
    typing = typo.typing

    match command:
        case TypoCharCommand(ch=ch):
            if ch:
                typing.push_char(str(ch))
                world.state.sfx_queue.append(
                    SfxRequest(_typeclick_sfx(world, caller=RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_CHAR), None),
                )
        case TypoBackspaceCommand():
            typing.backspace()
            world.state.sfx_queue.append(
                SfxRequest(_typeclick_sfx(world, caller=RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_BACKSPACE), None),
            )
        case TypoSubmitCommand():
            if not typing.text:
                return
            world.state.sfx_queue.append(SfxRequest(SfxId.UI_TYPEENTER, None))
            active_mask = [bool(entry.active) for entry in world.creatures.entries]
            target_idx = typo.names.find_by_name(typing.text, active_mask=active_mask)
            entered = typing.submit(matched=target_idx is not None)
            typo.pending_fire_target = None
            typo.pending_reload = False
            if entered is None:
                return
            if target_idx is not None:
                creature = world.creatures.entries[int(target_idx)]
                if creature.active:
                    typo.pending_fire_target = Vec2(float(creature.pos.x), float(creature.pos.y))
                return
            if entered == "reload":
                typo.pending_reload = True
        case _:
            raise RuntimeError(f"unhandled Typ-o command: {type(command).__name__}")


def typo_before_step(world: WorldState) -> None:
    for player in world.players:
        enforce_typo_player_frame(player)


def typo_mode_update(world: WorldState, *, elapsed_ms: float, dt_ms: float) -> None:
    # After firing, native stomps player 0 to the shotgun with 30 ammo, without
    # `weapon_assign_player`: the reset pistol's clip stays.
    player = world.players[0]
    player.weapon.weapon_id = TYPO_WEAPON_ID
    player.weapon.ammo = 30.0
    typo = world.state.typo
    typo.spawn_cooldown_ms -= int(dt_ms) * len(world.players)
    while typo.spawn_cooldown_ms < 0:
        typo.spawn_cooldown_ms = max(100, typo.spawn_cooldown_ms + 3500 - int(elapsed_ms) // 800)
        # `typo_gameplay_update_and_render` (0x00445af4..0x00445c15): float literals at PC24;
        # `fsin`/`fcos` stay wide until the next op rounds.
        tint_t = float(int(elapsed_ms) + 1)
        tint = RGBA(
            clamp01(x87_pc24_add(x87_pc24_mul(tint_t, f32(0.00000833333343)), f32(0.3))),
            clamp01(x87_pc24_add(x87_pc24_mul(tint_t, 10000.0), f32(0.3))),
            clamp01(x87_pc24_add(math.sin(x87_pc24_mul(tint_t, f32(0.000100000005))), f32(0.3))),
            1.0,
        )
        y = x87_pc24_add(x87_pc24_cos_mul(x87_pc24_mul(float(int(elapsed_ms)), f32(0.001)), 256.0), TERRAIN_SIZE * 0.5)
        for pos, type_id in (
            (Vec2(x87_pc24_add(TERRAIN_SIZE, 64.0), y), CreatureTypeId.SPIDER_SP2),
            (Vec2(-64.0, y), CreatureTypeId.ALIEN),
        ):
            creature_idx = creature_spawn_tinted(world, pos, tint, type_id)
            if creature_idx is None:
                continue
            typo.names.assign_random(
                creature_idx,
                world.state.rng,
                score_xp=world.state.highscore_score_xp,
                active_mask=[entry.active for entry in world.creatures.entries],
                dictionary_words=typo.dictionary_words,
                highscore_names=typo.highscore_names,
            )


def typo_post_step(world: WorldState) -> None:
    state = world.state
    state.bonuses.weapon_power_up = 0.0
    state.bonuses.reflex_boost = 0.0
    state.time_scale_active = False
    state.bonus_pool.reset()


def typo_input_transform(world: WorldState, inputs: Sequence[PlayerInput]) -> list[PlayerInput]:
    if not inputs:
        world.state.typo.pending_fire_target = None
        world.state.typo.pending_reload = False
        return []

    typo = world.state.typo
    primary = inputs[0]
    # Typ-o fires and reloads only through typed words; player fire/reload
    # input has no effect.
    aim = primary.aim if typo.pending_fire_target is None else typo.pending_fire_target
    fire_down = fire_pressed = typo.pending_fire_target is not None
    reload_pressed = bool(typo.pending_reload)

    typo.pending_fire_target = None
    typo.pending_reload = False

    transformed_primary = msgspec.structs.replace(
        primary,
        move=Vec2(),
        aim=Vec2(float(aim.x), float(aim.y)),
        fire_down=bool(fire_down),
        fire_pressed=bool(fire_pressed),
        reload_pressed=bool(reload_pressed),
        reload_down=False,
    )
    return [transformed_primary]
