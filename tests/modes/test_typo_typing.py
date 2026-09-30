from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.commands import TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import DeterministicSession
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from crimson.typo.names import CreatureNameTable
from crimson.typo.runtime import apply_typo_command, typo_mode_update
from crimson.typo.state import reset_typo_state
from crimson.typo.typing import TYPING_MAX_CHARS, TypingBuffer
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.helpers import ScriptedCrand


def test_typing_buffer_backspace_and_max_len() -> None:
    buf = TypingBuffer()
    buf.backspace()
    assert buf.text == ""

    for _ in range(TYPING_MAX_CHARS + 10):
        buf.push_char("a")
    assert buf.text == "a" * TYPING_MAX_CHARS

    buf.backspace()
    assert buf.text == "a" * (TYPING_MAX_CHARS - 1)


def test_typing_buffer_submit_noop_on_empty() -> None:
    buf = TypingBuffer()
    result = buf.submit(matched=False)
    assert result is None
    assert buf.submit_count == 0
    assert buf.match_count == 0


def test_typing_buffer_submit_counts_match_and_clears_text() -> None:
    buf = TypingBuffer(text="alpha")
    result = buf.submit(matched=True)
    assert result == "alpha"
    assert buf.text == ""
    assert buf.submit_count == 1
    assert buf.match_count == 1


def test_typing_buffer_submit_counts_reload_as_submit_only() -> None:
    buf = TypingBuffer(text="reload")
    result = buf.submit(matched=False)
    assert result == "reload"
    assert buf.text == ""
    assert buf.submit_count == 1
    assert buf.match_count == 0


def test_typo_submit_fires_at_the_named_creature_for_one_tick(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(
        world.state.typo,
        creature_capacity=len(world.creatures.entries),
    )
    world.state.game_mode = GameMode.TYPO
    player = world.players[0]
    weapon_assign_player(player, WeaponId.SHOTGUN, state=world.state)
    creature = world.creatures.entries[7]
    creature.active = True
    creature.pos = Vec2(321.0, 654.0)
    world.state.typo.names.names[7] = "alpha"
    world.state.typo.typing.text = "alpha"
    session = DeterministicSession(
        world=world,
        perk_progression_enabled=False,
    )

    session.step_tick(dt=1.0 / 60.0, inputs=[PlayerInput()], commands=[TypoSubmitCommand(player_index=0)])

    assert player.aim == Vec2(321.0, 654.0)
    assert world.state.shots_fired == 12

    session.step_tick(dt=1.0 / 60.0, inputs=[PlayerInput(fire_down=True, fire_pressed=True)])

    # The aim point stays on the last target; player fire input does nothing.
    assert player.aim == Vec2(321.0, 654.0)
    assert world.state.shots_fired == 12


def test_typo_char_command_tags_exact_typeclick_caller(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(world.state.typo, creature_capacity=len(world.creatures.entries))
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    apply_typo_command(world, TypoCharCommand(player_index=0, ch="a"))

    assert sfx_ids(world.state.sfx_queue) == [SfxId.UI_TYPECLICK_01]
    assert [record.caller for record in world.state.rng.records_since()] == [
        RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_CHAR,
    ]


def test_typo_backspace_command_tags_exact_typeclick_caller(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(world.state.typo, creature_capacity=len(world.creatures.entries))
    world.state.typo.typing.text = "ab"
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    apply_typo_command(world, TypoBackspaceCommand(player_index=0))

    assert sfx_ids(world.state.sfx_queue) == [SfxId.UI_TYPECLICK_01]
    assert world.state.typo.typing.text == "a"
    assert [record.caller for record in world.state.rng.records_since()] == [
        RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_BACKSPACE,
    ]


def test_typo_spawn_step_tags_exact_spawn_tinted_callers(mocker) -> None:

    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0), experience=130))
    reset_typo_state(world.state.typo, creature_capacity=len(world.creatures.entries))
    world.state.rng = RecordingCrand(Crand(0x1234))
    world.state.highscore_score_xp = 7
    assign_random = mocker.spy(CreatureNameTable, "assign_random")

    typo_mode_update(world, elapsed_ms=0.0, dt_ms=1.0)

    callers = [
        record.caller
        for record in world.state.rng.records_since()
        if record.caller
        in {
            RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
            RngCallerStatic.CREATURE_SPAWN_TINTED_HEADING,
            RngCallerStatic.CREATURE_SPAWN_TINTED_SIZE,
        }
    ]
    # Native creature_spawn_tinted draws three rands per spawn: the alloc-slot
    # phase seed, then heading, then size.
    assert callers == [
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.CREATURE_SPAWN_TINTED_HEADING,
        RngCallerStatic.CREATURE_SPAWN_TINTED_SIZE,
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.CREATURE_SPAWN_TINTED_HEADING,
        RngCallerStatic.CREATURE_SPAWN_TINTED_SIZE,
    ]
    assert [call.kwargs["score_xp"] for call in assign_random.call_args_list] == [7, 7]
