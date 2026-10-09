from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.sim.mode_updates import QuestSpawnState
from crimson.sim.run_result import RunOutcome
from crimson.sim.sessions import DeterministicSession
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.factories import player_input
from tests.support.world_runtime import WorldRuntimeHost


def _build_session(*, seed: int = 101, level: str = "1.1") -> tuple[DeterministicSession, QuestSpawnState]:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    runtime.reset(seed=int(seed), player_count=1)
    quest = quest_by_level(QuestLevel.parse(level))
    assert quest is not None
    entries = tuple(
        build_quest_spawn_table(
            quest,
            QuestContext(player_count=1, rng=Crand(int(seed))),
            ),
    )
    spawn_state = QuestSpawnState(spawn_entries=entries)
    runtime.world.state.game_mode = GameMode.QUESTS
    runtime.world.state.quest_level = quest.level
    session = DeterministicSession(
        world=runtime.world,
        perk_progression_enabled=True,
        mode_state=spawn_state,
    )
    return session, spawn_state


def test_quest_session_clears_reflex_boost_when_quest_is_idle_complete() -> None:
    session, spawn_state = _build_session(seed=101)
    spawn_state.spawn_entries = ()
    session.world.state.bonuses.reflex_boost = 0.25471345
    session.world.state.time_scale_active = True

    _tick = session.step_tick(
        dt=0.054,
        inputs=[player_input()],
    )

    assert spawn_state.spawn_timeline_ms == 0.0
    assert session.world.state.bonuses.reflex_boost == 0.0
    assert session.world.state.time_scale_active is False


def _effects_after_first_spawn(*, detail_preset: int) -> int:
    session, _spawn_state = _build_session(seed=101, level="1.3")
    session.world.state.detail_preset = detail_preset
    creatures = session.world.creatures.entries
    while not any(creature.active for creature in creatures):
        session.step_tick(dt=1.0 / 60.0, inputs=[player_input(aim=Vec2(512.0, 512.0))])
    return len(session.world.state.effects.iter_active())


def test_quest_spawn_bursts_follow_the_session_detail_preset() -> None:
    # Native effect_spawn skips every other effect below detail preset 3.
    assert _effects_after_first_spawn(detail_preset=1) * 2 == _effects_after_first_spawn(detail_preset=5)


def test_death_replaces_pending_quest_results() -> None:
    session, spawn_state = _build_session(seed=101)
    spawn_state.completed = True
    assert session.terminal_outcome() is RunOutcome.QUEST_COMPLETED

    player = session.world.players[0]
    player.health = 0.0
    player.death_timer = -1.0

    assert session.terminal_outcome() is RunOutcome.DEATH
