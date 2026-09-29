"""`tutorial_timeline_update` vs the port's `tutorial_timeline_update`.

Each case seeds the tutorial globals, a few creatures (optionally the hint carrier, alive or a culled
corpse) and a bonus, runs one native update and one port update from the same `crt_rand` seed, and
compares the tutorial state, the forced player health and experience, the bonus pool, the creatures
it spawns (with the carrier's packed bonus args) and the RNG state. Stages 1 and 3 read raw keys;
the fake Grim interface reports every key up, and the port sees no move or fire input.
"""

from __future__ import annotations

import random
import struct

from crimson.bonuses import BonusId
from crimson.creatures.runtime import pack_bonus_on_death_args
from crimson.creatures.spawn_ids import CreatureFlags
from crimson.game_modes import GameMode
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from crimson.tutorial.timeline import tutorial_timeline_update
from crimson.weapon_runtime import prepare_weapon_availability
from grim.geom import Vec2

from ._support import CREATURE_LAYOUT, CREATURE_POOL_SLOTS, CREATURE_STRIDE, PLAYER_OFFSETS, prepare_gameplay

_PLAYER_EXPERIENCE = 0xAC
_BONUS_STRIDE = 0x1C
_GRIM_SET_COLOR_SLOT = 69  # vtable +0x114


def _fake_grim_interface(oracle) -> int:
    """Every key (`grim_is_key_active`, +0x80) reads as up; `grim_set_color` (+0x114) pops its four floats."""

    ret_one_arg = oracle.load_code(b"\x31\xc0\xc2\x04\x00")  # xor eax, eax; ret 4
    ret_four_args = oracle.load_code(b"\xc2\x10\x00")  # ret 0x10
    slots = [ret_one_arg] * 256
    slots[_GRIM_SET_COLOR_SLOT] = ret_four_args
    vtable = oracle.alloc(0x400, data=struct.pack("<256I", *slots))
    return oracle.alloc(0x10, data=struct.pack("<I", vtable))


def _python_world(seed: int) -> WorldState:
    world = WorldState.build(hardcore=False, quest_fail_retry_count=0)
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    world.state.game_mode = GameMode.TUTORIAL
    world.state.detail_preset = 5
    world.state.rng.srand(seed)
    prepare_weapon_availability(world.state)
    return world


def _seed_creature(oracle, world: WorldState, index: int, *, active: bool, health: float, flags: int) -> None:
    address = oracle.resolve("creature_pool") + index * CREATURE_STRIDE
    oracle.write_u8(address + CREATURE_LAYOUT["active"][0], int(active))
    oracle.write_f32(address + CREATURE_LAYOUT["health"][0], health)
    oracle.write_f32(address + CREATURE_LAYOUT["lifecycle_stage"][0], 16.0 if health > 0.0 else -20.0)
    oracle.write_u32(address + CREATURE_LAYOUT["flags"][0], flags)
    creature = world.creatures.entries[index]
    creature.active = active
    creature.hp = health
    creature.lifecycle_stage = 16.0 if health > 0.0 else -20.0
    creature.flags = CreatureFlags(flags)


def test_tutorial_timeline_matches_native(oracle) -> None:
    prepare_gameplay(oracle)
    oracle.write_u32("grim_interface_ptr", _fake_grim_interface(oracle))
    oracle.write_u32("config_game_mode", int(GameMode.TUTORIAL))
    oracle.write_u32("config_detail_preset", 5)
    oracle.stub("tutorial_prompt_dialog", 0)
    oracle.stub("sfx_play", 0)
    pristine = oracle.snapshot()
    pool = oracle.resolve("creature_pool")
    bonus_pool = oracle.resolve("bonus_pool")
    player = oracle.resolve("player_state_table")

    rng = random.Random(0x408990)
    failures: list[str] = []
    cases = spawned = 0
    for _ in range(600):
        stage = rng.choice((-1, 0, 2, 4, 5, 5, 5, 6, 7))
        # Stages 0 and 2 must not step into the key-reading stages 1 and 3.
        transition = rng.choice((-1, rng.randrange(0, 1100), rng.randrange(-1000, -1)))
        if stage in (0, 2) and transition < -1:
            transition = -1
        timer = rng.randrange(0, 8000)
        repeat = rng.randrange(0, 9)
        hint_index = rng.randrange(-1, 5)
        hint_alpha = rng.randrange(0, 1001)
        latch = rng.random() < 0.5
        pending = rng.randrange(0, 3)
        experience = rng.randrange(0, 4000)
        dt_ms = rng.choice((16, 17, rng.randrange(1, 120)))
        fillers = rng.choice((0, 0, 2))
        carrier = rng.choice((None, "dead", "alive"))
        bonus = rng.random() < 0.3
        seed = rng.getrandbits(32)
        cases += 1

        oracle.restore(pristine)
        world = _python_world(seed)
        oracle.rand_state = seed
        tutorial = world.state.tutorial
        for name, value in (
            ("tutorial_stage_index", stage),
            ("tutorial_stage_timer", timer),
            ("tutorial_stage_transition_timer", transition),
            ("tutorial_repeat_spawn_count", repeat),
            ("tutorial_hint_index", hint_index),
            ("tutorial_hint_alpha", hint_alpha),
            ("perk_pending_count", pending),
        ):
            oracle.write_u32(name, value & 0xFFFF_FFFF)
        oracle.write_u8("tutorial_hint_bonus_consumed_latch", int(latch))
        oracle.write_u32(player + _PLAYER_EXPERIENCE, experience)
        oracle.write_f32(player + PLAYER_OFFSETS["health"], 50.0)
        tutorial.stage_index, tutorial.stage_timer_ms, tutorial.stage_transition_timer_ms = stage, timer, transition
        tutorial.repeat_spawn_count, tutorial.hint_index, tutorial.hint_alpha = repeat, hint_index, hint_alpha
        tutorial.hint_fade_in = latch
        world.state.perk_selection.pending_count = pending
        world.players[0].experience = experience
        world.players[0].health = 50.0

        for index in range(fillers):
            _seed_creature(oracle, world, index, active=True, health=40.0, flags=0)
        carrier_index = fillers
        if carrier is not None:
            _seed_creature(
                oracle,
                world,
                carrier_index,
                active=carrier == "alive",
                health=30.0 if carrier == "alive" else 0.0,
                flags=int(CreatureFlags.BONUS_ON_DEATH),
            )
            oracle.write_u32("tutorial_hint_bonus_ptr", pool + carrier_index * CREATURE_STRIDE)
            tutorial.hint_bonus_creature_ref = carrier_index
        if bonus:
            oracle.write_u32(bonus_pool, int(BonusId.POINTS))
            oracle.write_f32(bonus_pool + 0x08, 10.0)
            oracle.write_f32(bonus_pool + 0x10, 400.0)
            oracle.write_f32(bonus_pool + 0x14, 400.0)
            oracle.write_u32(bonus_pool + 0x18, 500)
            world.state.bonus_pool.seed_tutorial_entry(0, pos=Vec2(400.0, 400.0), bonus_id=BonusId.POINTS, amount=500)

        oracle.write_u32("frame_dt_ms", dt_ms)
        oracle.call("tutorial_timeline_update")
        tutorial_timeline_update(world, dt_ms=dt_ms)

        case = (
            f"stage={stage} timer={timer} transition={transition} repeat={repeat} hint={hint_index}/{hint_alpha}"
            f" latch={latch} carrier={carrier} fillers={fillers} bonus={bonus} dt={dt_ms} seed=0x{seed:08x}"
        )

        def check(field: str, native: object, python: object, case: str = case) -> None:
            if native != python:
                failures.append(f"{case}: {field} native={native!r} port={python!r}")

        check("stage_index", oracle.read_i32("tutorial_stage_index"), tutorial.stage_index)
        check("stage_timer", oracle.read_i32("tutorial_stage_timer"), tutorial.stage_timer_ms)
        check("transition", oracle.read_i32("tutorial_stage_transition_timer"), tutorial.stage_transition_timer_ms)
        check("repeat", oracle.read_i32("tutorial_repeat_spawn_count"), tutorial.repeat_spawn_count)
        check("hint_index", oracle.read_i32("tutorial_hint_index"), tutorial.hint_index)
        check("hint_alpha", oracle.read_i32("tutorial_hint_alpha"), tutorial.hint_alpha)
        check("latch", bool(oracle.read_u8("tutorial_hint_bonus_consumed_latch")), tutorial.hint_fade_in)
        native_carrier = oracle.read_u32("tutorial_hint_bonus_ptr")
        python_carrier = tutorial.hint_bonus_creature_ref
        check(
            "carrier",
            None if native_carrier == 0 else (native_carrier - pool) // CREATURE_STRIDE,
            python_carrier,
        )
        check("health", oracle.read_f32(player + PLAYER_OFFSETS["health"]), world.players[0].health)
        check("experience", oracle.read_i32(player + _PLAYER_EXPERIENCE), world.players[0].experience)
        for slot in range(16):
            address = bonus_pool + slot * _BONUS_STRIDE
            entry = world.state.bonus_pool.entries[slot]
            native_id = oracle.read_i32(address)
            check(f"bonus[{slot}].id", native_id, int(entry.bonus_id))
            if native_id:
                check(f"bonus[{slot}].amount", oracle.read_i32(address + 0x18), entry.amount)
                check(f"bonus[{slot}].pos", (oracle.read_f32(address + 0x10), oracle.read_f32(address + 0x14)), (entry.pos.x, entry.pos.y))
        for index in range(fillers + 1, CREATURE_POOL_SLOTS):
            address = pool + index * CREATURE_STRIDE
            native = oracle.read_fields(address, CREATURE_LAYOUT)
            python = world.creatures.entries[index]
            check(f"creature[{index}].active", int(native["active"]), int(python.active))
            if not native["active"]:
                continue
            spawned += 1
            check(f"creature[{index}].type", native["type_id"], int(python.type_id))
            check(f"creature[{index}].pos", (native["pos_x"], native["pos_y"]), (python.pos.x, python.pos.y))
            check(f"creature[{index}].health", native["health"], python.hp)
            if python.flags & CreatureFlags.BONUS_ON_DEATH and python.bonus_id is not None:
                override = -1 if python.bonus_duration_override is None else python.bonus_duration_override
                packed = pack_bonus_on_death_args(python.bonus_id, override)
                check(f"creature[{index}].bonus_args", native["link_index"], packed)
        check("rand_state", oracle.rand_state, world.state.rng.state)

    assert spawned > 50, f"only {spawned} creatures spawned over {cases} cases"
    assert not failures, "\n".join(failures[:40]) + f"\n{len(failures)} mismatches"
