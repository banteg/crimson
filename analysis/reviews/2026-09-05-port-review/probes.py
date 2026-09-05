from __future__ import annotations

import json
import struct
from unittest.mock import patch

from crimson.aim_schemes import AimScheme
from crimson.bonuses.apply import bonus_apply
from crimson.bonuses.ids import BonusId
from crimson.gameplay import GameplayState, _resolve_aim_scheme_for_update, _resolve_move_mode_for_update, player_update
from crimson.local_input import clear_input_edges
from crimson.math_parity import NATIVE_QUARTER_PI, f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from crimson.movement_controls import MovementControlType
from crimson.net.rollback import RollbackController
from crimson.owner_ref import OwnerRef
from crimson.perks.ids import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, LocalInputProvider
from crimson.sim.presentation_reactions import build_post_apply_reaction
from crimson.sim.session_builders import build_quest_session
from crimson.sim.state_types import PlayerState
from crimson.sim.tick_runner import TickRunner
from crimson.world.sim_world_state import SimWorldState
from grim.geom import Vec2
from tests.support.builders.input_providers import ReadyTickInputProvider, StaticLocalInputRuntime
from tests.support.helpers import ScriptedCrand

out = {}
inp = PlayerInput(
    move=Vec2(0, -1),
    move_mode=MovementControlType.RELATIVE,
    aim_scheme=AimScheme.KEYBOARD,
    reload_down=True,
    fire_pressed=True,
    move_forward_pressed=True,
    move_backward_pressed=False,
    turn_left_pressed=False,
    turn_right_pressed=False,
)
cleared = clear_input_edges([inp])[0]
out["input_field_loss"] = {
    "reload_down": [inp.reload_down, cleared.reload_down],
    "resolved_move_mode": [str(_resolve_move_mode_for_update(x, GameplayState())) for x in (inp, cleared)],
    "resolved_aim_scheme": [str(_resolve_aim_scheme_for_update(x, GameplayState())) for x in (inp, cleared)],
}
assert cleared.reload_down is False and cleared.move_mode is None and cleared.aim_scheme is None

rt = StaticLocalInputRuntime(inputs=(PlayerInput(fire_down=True, fire_pressed=True),))
provider = LocalInputProvider(player_count=1, runtime=rt)
provider.begin_frame(FrameContext(dt_seconds=1 / 120, tick_dt_seconds=1 / 60, frame_index=1, candidate_ticks=0))
rt.inputs = (PlayerInput(fire_pressed=False),)
provider.begin_frame(FrameContext(dt_seconds=1 / 120, tick_dt_seconds=1 / 60, frame_index=2, candidate_ticks=1))
tick = provider.pull_tick(0, 1 / 60).tick
out["zero_tick_edge_loss"] = {
    "pressed_in_first_render_frame": True,
    "first_sim_tick_fire_pressed": tick.inputs[0].fire_pressed,
}
assert tick.inputs[0].fire_pressed is False

rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
state = GameplayState(rng=rng, preserve_bugs=True)
player = PlayerState(index=0, pos=Vec2(100, 100), man_bomb_timer=3.9)
player.perk_counts[int(PerkId.MAN_BOMB)] = 1
player_update(player, PlayerInput(aim=Vec2(101, 100)), 0.2, state)
angles = [p.angle for p in state.projectiles.entries if p.active]
expected = [
    x87_pc24_sub(x87_pc24_add(x87_pc24_mul(0.0, f32(0.01)), x87_pc24_mul(float(i), NATIVE_QUARTER_PI)), 0.25)
    for i in range(8)
]
bits = lambda x: hex(struct.unpack("<I", struct.pack("<f", x))[0])
out["man_bomb_pc24"] = [
    {"index": i, "port": a, "native_expression": b, "port_bits": bits(a), "native_bits": bits(b)}
    for i, (a, b) in enumerate(zip(angles, expected))
    if a != b
]
assert out["man_bomb_pc24"]


def freeze_run(native_guards: bool):
    sim = SimWorldState(preserve_bugs=True)
    world = sim.world_state
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    c = world.creatures.entries[0]
    c.active, c.hp, c.pos = True, 1.0, Vec2(200, 200)
    world.state.projectiles.spawn(
        pos=Vec2(200, 200), angle=0.0, type_id=ProjectileTemplateId.PISTOL, owner=OwnerRef.from_local_player(0),
    )
    world.state.bonus_pool.spawn_at(world.players[0].pos, BonusId.FREEZE, state=world.state, emit_burst=False)
    from crimson.game_modes import GameMode
    from crimson.sim.sessions import DeterministicSession

    session = DeterministicSession(
        world=world,
        world_size=1024.0,
        damage_scale_by_type=sim.damage_scale_by_type,
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    def unfiltered(*args, **kwargs):
        kwargs["freeze_corpse_indices"] = None
        return bonus_apply(*args, **kwargs)

    with patch("crimson.bonuses.pool.bonus_apply", unfiltered if native_guards else bonus_apply):
        result = session.step_tick(dt=1 / 60, inputs=[PlayerInput(aim=Vec2(600, 512))])
    freeze_callers = {RngCallerStatic.BONUS_APPLY_FREEZE_SHARD_ANGLE, RngCallerStatic.BONUS_APPLY_FREEZE_SHATTER_ANGLE}
    return {
        "deaths": len(result.step.events.deaths),
        "freeze_pickups": sum(p.bonus_id == BonusId.FREEZE for p in result.step.events.pickups),
        "freeze_angle_draws": sum(r.caller in freeze_callers for r in world.state.rng.records_since()),
        "all_rng_draws": world.state.rng.calls,
        "corpse_active": c.active,
    }


out["freeze_same_tick_kill"] = {"current": freeze_run(False), "without_tick_start_filter": freeze_run(True)}
assert out["freeze_same_tick_kill"]["current"]["deaths"] == 1
assert out["freeze_same_tick_kill"]["current"]["freeze_pickups"] == 1
assert out["freeze_same_tick_kill"]["current"]["freeze_angle_draws"] == 0
assert out["freeze_same_tick_kill"]["without_tick_start_filter"]["freeze_angle_draws"] == 9


def quest_batch(start_ms):
    sim = SimWorldState()
    session, spawn = build_quest_session(
        world=sim.world_state,
        world_size=1024.0,
        damage_scale_by_type=sim.damage_scale_by_type,
        detail_preset=5,
        violence_disabled=0,
        game_tune_started=False,
        demo_mode_active=False,
        apply_world_dt_steps=True,
        finalize_post_render_lifecycle=True,
        spawn_entries=(),
        quest_level=None,
        start_weapon_id=None,
    )
    spawn.completion_transition_ms = start_ms
    immediate = []

    def flags(result):
        q = build_post_apply_reaction(tick_result=result, quest_state=spawn).quest
        return [q.play_hit_sfx, q.play_completion_music]

    runner = TickRunner(session=session, input_provider=ReadyTickInputProvider(inputs=(PlayerInput(),)))
    batch = runner.advance_ticks(
        start_tick=0, ticks_requested=2, tick_dt=1 / 60, after_tick=lambda r: immediate.append(flags(r)),
    )
    return {"at_each_tick": immediate, "after_batch": [flags(r) for r in batch.completed_results]}


out["quest_reaction_batching"] = {str(t): quest_batch(t) for t in (810.0, 2001.0, 790.0)}
assert out["quest_reaction_batching"]["810.0"] == {
    "at_each_tick": [[True, False], [False, False]],
    "after_batch": [[False, False], [False, False]],
}
assert out["quest_reaction_batching"]["2001.0"] == {
    "at_each_tick": [[False, True], [False, False]],
    "after_batch": [[False, False], [False, False]],
}
assert out["quest_reaction_batching"]["790.0"] == {
    "at_each_tick": [[False, False], [True, False]],
    "after_batch": [[True, False], [True, False]],
}

rb = RollbackController(player_count=2, local_slot_index=0, input_delay_ticks=0)
original = []
batches = []
for i in range(4):
    batches.append(rb.queue_local_input([0.1 * (i + 1), 0.0, 100.0, 100.0, 0]))
    original.append(rb.pop_frame())
rebuilt = rb.rebuild_emitted_from(1)
out["rollback_local_history"] = {
    "original_local_inputs": [f.frame_inputs[0] for f in original[1:]],
    "rebuilt_local_inputs": [f.frame_inputs[0] for f in rebuilt],
    "fourth_packet_tick_indices": [s.tick_index for s in batches[-1].samples],
}
assert rebuilt[0].frame_inputs[0] != original[1].frame_inputs[0]

print(json.dumps(out, indent=2))
