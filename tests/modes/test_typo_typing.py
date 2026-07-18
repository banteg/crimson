from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from crimson.sim.sessions import DeterministicSession, MidStepContext, SessionModeRuntime
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from crimson.typo.names import CreatureNameTable
from crimson.typo.runtime import apply_typo_command, typo_input_transform, typo_mid_step
from crimson.typo.state import reset_typo_state
from crimson.typo.typing import TYPING_MAX_CHARS, TypingBuffer
from grim.geom import Vec2
from grim.sfx_map import SfxId
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


def test_typo_commands_apply_before_input_transform(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(
        world.state.typo,
        creature_capacity=len(world.creatures.entries),
    )
    seen_typing_text: list[str] = []

    class _StopAfterTransform(RuntimeError):
        pass

    class _TransformObserver(SessionModeRuntime):
        world: WorldState
        seen_typing_text: list[str]

        def transform_inputs(self, inputs: list[PlayerInput]) -> list[PlayerInput]:
            _ = inputs
            self.seen_typing_text.append(str(self.world.state.typo.typing.text))
            raise _StopAfterTransform

    session = DeterministicSession(
        world=world,
        world_size=1024.0,
        damage_scale_by_type={},
        game_mode=GameMode.TYPO,
        perk_progression_enabled=False,
        mode_runtime=_TransformObserver(world=world, seen_typing_text=seen_typing_text),
    )

    with pytest.raises(_StopAfterTransform):
        session.step_tick(
            dt=1.0 / 60.0,
            inputs=[PlayerInput()],
            commands=[TypoCharCommand(player_index=0, ch="a")],
        )

    assert seen_typing_text == ["a"]


def test_typo_submit_match_overrides_only_one_tick(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(
        world.state.typo,
        creature_capacity=len(world.creatures.entries),
    )
    creature = world.creatures.entries[7]
    creature.active = True
    creature.pos = Vec2(321.0, 654.0)
    world.state.typo.names.names[7] = "alpha"
    world.state.typo.typing.text = "alpha"

    apply_typo_command(world, TypoSubmitCommand(player_index=0))

    baseline = [PlayerInput(aim=Vec2(10.0, 20.0))]
    transformed0 = typo_input_transform(world, baseline)
    transformed1 = typo_input_transform(world, baseline)

    assert transformed0[0].aim == Vec2(321.0, 654.0)
    assert transformed0[0].fire_down is True
    assert transformed0[0].fire_pressed is True
    assert transformed1[0].aim == Vec2(10.0, 20.0)
    assert transformed1[0].fire_down is False
    assert transformed1[0].fire_pressed is False


def test_typo_char_command_tags_exact_typeclick_caller(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(world.state.typo, creature_capacity=len(world.creatures.entries))
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    apply_typo_command(world, TypoCharCommand(player_index=0, ch="a"))

    assert world.state.sfx_queue == [SfxId.UI_TYPECLICK_01]
    assert [record.caller for record in world.state.rng.records_since()] == [
        RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_CHAR,
    ]


def test_typo_backspace_command_tags_exact_typeclick_caller(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(world.state.typo, creature_capacity=len(world.creatures.entries))
    world.state.typo.typing.text = "ab"
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    apply_typo_command(world, TypoBackspaceCommand(player_index=0))

    assert world.state.sfx_queue == [SfxId.UI_TYPECLICK_01]
    assert world.state.typo.typing.text == "a"
    assert [record.caller for record in world.state.rng.records_since()] == [
        RngCallerStatic.TYPO_GAMEPLAY_TYPECLICK_BACKSPACE,
    ]


def test_typo_spawn_step_tags_exact_spawn_tinted_callers(mocker) -> None:
    from crimson.sim.world_state import WorldState

    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0), experience=130))
    reset_typo_state(world.state.typo, creature_capacity=len(world.creatures.entries))
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.highscore_score_xp = 7
    assign_random = mocker.spy(CreatureNameTable, "assign_random")

    typo_mid_step(
        MidStepContext(
            world=world,
            elapsed_before_ms=0.0,
            dt_sim_ms=1.0,
            dt_raw_ms=1.0,
            world_size=1024.0,
        ),
    )

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
