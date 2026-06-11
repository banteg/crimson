from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2
from grim.sfx_map import SfxId

from ..creatures.spawn import CreatureAiMode, CreatureFlags, CreatureInit, CreatureTypeId
from ..rng_caller_static import RngCallerStatic
from ..sim.input import PlayerInput
from ..sim.input_providers import TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from ..sim.world_state import WorldState
from .player import enforce_typo_player_frame
from .spawns import tick_typo_spawns

if TYPE_CHECKING:
    from ..sim.sessions import MidStepContext, PostStepContext


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
                    _typeclick_sfx(world, caller=RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_CHAR),
                )
        case TypoBackspaceCommand():
            typing.backspace()
            world.state.sfx_queue.append(
                _typeclick_sfx(world, caller=RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_BACKSPACE),
            )
        case TypoSubmitCommand():
            if not typing.text:
                return
            world.state.sfx_queue.append(SfxId.UI_TYPEENTER)
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
        enforce_typo_player_frame(player, state=world.state)


def typo_mid_step(ctx: MidStepContext) -> None:
    typo = ctx.world.state.typo
    cooldown, spawns = tick_typo_spawns(
        elapsed_ms=int(ctx.elapsed_before_ms),
        spawn_cooldown_ms=int(typo.spawn_cooldown_ms),
        frame_dt_ms=int(ctx.dt_sim_ms),
        player_count=len(ctx.world.players),
        world_width=float(ctx.world_size),
        world_height=float(ctx.world_size),
    )
    typo.spawn_cooldown_ms = int(cooldown)
    for call in spawns:
        # creature_spawn_tinted allocates via creature_alloc_slot, which seeds
        # phase_seed = float(crt_rand() & 0x17f) before the heading/size draws.
        phase_seed = float(ctx.world.state.rng.rand_tagged(RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED) & 0x17F)
        heading = float(ctx.world.state.rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TINTED_HEADING) % 314) * 0.01
        size = float(ctx.world.state.rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TINTED_SIZE) % 20 + 47)
        flags = CreatureFlags(0)
        move_speed = 1.7
        if int(call.type_id) in (int(CreatureTypeId.SPIDER_SP1), int(CreatureTypeId.SPIDER_SP2)):
            flags |= CreatureFlags.AI7_LINK_TIMER
            move_speed *= 1.2
            size *= 0.8

        creature_idx = ctx.world.creatures.spawn_init(
            CreatureInit(
                origin_template_id=0,
                pos=call.pos,
                heading=float(heading),
                phase_seed=float(phase_seed),
                type_id=call.type_id,
                flags=flags,
                ai_mode=CreatureAiMode.CHASE_PLAYER,
                health=1.0,
                max_health=1.0,
                move_speed=float(move_speed),
                reward_value=1.0,
                size=float(size),
                contact_damage=100.0,
                tint=call.tint_rgba.to_tuple(),
            ),
        )
        if creature_idx is None:
            continue
        active_mask = [bool(entry.active) for entry in ctx.world.creatures.entries]
        typo.names.assign_random(
            int(creature_idx),
            ctx.world.state.rng,
            score_xp=int(ctx.world.players[0].experience) if ctx.world.players else 0,
            active_mask=active_mask,
            dictionary_words=typo.dictionary_words,
            highscore_names=typo.highscore_names,
        )


def typo_post_step(ctx: PostStepContext) -> None:
    state = ctx.world.state
    state.bonuses.weapon_power_up = 0.0
    state.bonuses.reflex_boost = 0.0
    state.time_scale_active = False
    state.bonus_pool.reset()


def typo_input_transform(world: WorldState, inputs: list[PlayerInput]) -> list[PlayerInput]:
    if not inputs:
        world.state.typo.pending_fire_target = None
        world.state.typo.pending_reload = False
        return []

    typo = world.state.typo
    primary = inputs[0]
    aim = primary.aim
    fire_down = bool(primary.fire_down)
    fire_pressed = bool(primary.fire_pressed)
    reload_pressed = bool(primary.reload_pressed)

    if typo.pending_fire_target is not None:
        aim = typo.pending_fire_target
        fire_down = True
        fire_pressed = True
    if typo.pending_reload:
        reload_pressed = True

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
