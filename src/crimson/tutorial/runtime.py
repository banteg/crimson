from __future__ import annotations

from grim.sfx_map import SfxId

from ..creatures.runtime import CreatureFlags
from ..creatures.spawn import SpawnId
from ..gameplay import survival_check_level_up
from ..sim.input import PlayerInput
from ..sim.world_state import WorldState
from .state import TutorialOverlayState
from .timeline import TutorialFrameActions, tick_tutorial_timeline


def tutorial_before_step(world: WorldState) -> None:
    tutorial = world.state.tutorial
    tutorial.preserve_bugs = bool(world.state.preserve_bugs)
    hint_ref = tutorial.hint_bonus_creature_ref
    tutorial.hint_bonus_alive_before_tick = False
    if hint_ref is None or not (0 <= int(hint_ref) < len(world.creatures.entries)):
        return
    entry = world.creatures.entries[int(hint_ref)]
    tutorial.hint_bonus_alive_before_tick = bool(entry.active and entry.hp > 0.0)


def tutorial_input_transform(world: WorldState, inputs: list[PlayerInput]) -> list[PlayerInput]:
    tutorial = world.state.tutorial
    if inputs:
        primary = inputs[0]
        tutorial.move_active_this_tick = primary.move.length_sq() > 0.0
        tutorial.fire_active_this_tick = bool(primary.fire_pressed or primary.fire_down)
    else:
        tutorial.move_active_this_tick = False
        tutorial.fire_active_this_tick = False
    return list(inputs)


def _tutorial_overlay_from_actions(actions: TutorialFrameActions) -> TutorialOverlayState:
    return TutorialOverlayState(
        prompt_text=str(actions.prompt_text),
        prompt_alpha=float(actions.prompt_alpha),
        hint_text=str(actions.hint_text),
        hint_alpha=float(actions.hint_alpha),
    )


def tutorial_post_step(ctx) -> None:
    state = ctx.world.state
    tutorial = state.tutorial
    hint_ref = tutorial.hint_bonus_creature_ref
    hint_alive_after = False
    if hint_ref is not None and 0 <= int(hint_ref) < len(ctx.world.creatures.entries):
        entry = ctx.world.creatures.entries[int(hint_ref)]
        hint_alive_after = bool(entry.active and entry.hp > 0.0)
    hint_bonus_died = bool(tutorial.hint_bonus_alive_before_tick and not hint_alive_after)

    tutorial, actions = tick_tutorial_timeline(
        tutorial,
        frame_dt_ms=float(ctx.dt_sim_ms),
        any_move_active=bool(tutorial.move_active_this_tick),
        any_fire_active=bool(tutorial.fire_active_this_tick),
        creatures_none_active=not bool(ctx.world.creatures.iter_active()),
        bonus_pool_empty=not bool(state.bonus_pool.iter_active()),
        perk_pending_count=int(state.perk_selection.pending_count),
        hint_bonus_died=hint_bonus_died,
    )
    tutorial.move_active_this_tick = False
    tutorial.fire_active_this_tick = False
    tutorial.hint_bonus_alive_before_tick = False
    state.tutorial = tutorial
    state.tutorial_overlay = _tutorial_overlay_from_actions(actions)

    players = ctx.world.players
    if players:
        players[0].health = float(actions.force_player_health)
        if actions.force_player_experience is not None:
            players[0].experience = int(actions.force_player_experience)
            survival_check_level_up(players[0], state.perk_selection)

    if actions.play_levelup_sfx:
        state.sfx_queue.append(SfxId.UI_LEVELUP)

    for index, call in enumerate(actions.spawn_bonuses):
        # Native tutorial code overwrites slots 0..2 directly with 100-second
        # timers (no bonus_spawn_at clamp or 16-particle burst).
        spawned = state.bonus_pool.seed_tutorial_entry(
            index,
            pos=call.pos,
            bonus_id=call.bonus_id,
            amount=int(call.amount),
        )
        state.effects.spawn_burst(
            pos=spawned.pos,
            count=12,
            rng=state.rng,
            detail_preset=int(ctx.detail_preset),
        )

    for call in actions.spawn_templates:
        mapping, primary = ctx.world.creatures.spawn_template(
            call.template_id,
            call.pos,
            float(call.heading),
            state.rng,
        )
        _ = mapping
        if primary is None or actions.stage5_bonus_carrier_drop is None:
            continue
        if int(call.template_id) != int(SpawnId.ALIEN_CONST_WEAPON_BONUS_27):
            continue
        drop_id, drop_amount = actions.stage5_bonus_carrier_drop
        tutorial.hint_bonus_creature_ref = int(primary)
        if 0 <= int(primary) < len(ctx.world.creatures.entries):
            creature = ctx.world.creatures.entries[int(primary)]
            creature.flags |= CreatureFlags.BONUS_ON_DEATH
            creature.bonus_id = drop_id
            creature.bonus_duration_override = int(drop_amount)

    state.tutorial = tutorial
