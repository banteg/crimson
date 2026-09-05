from __future__ import annotations

from pathlib import Path

import pytest

from crimson.dbg.state_digest import session_digest
from crimson.persistence.save_status import GameStatus, GameStatusData
from grim.rand import RecordingCrand
from tests.support.builders.session import make_session


@pytest.mark.parametrize("component", ["cooldown", "camera", "inactive_creature", "effect_allocator", "mode_time", "terrain_queue"])
def test_session_digest_detects_state_omitted_from_compact_checkpoints(component: str) -> None:
    session, sim = make_session()
    before = session_digest(session)
    match component:
        case "cooldown":
            sim.players[0].weapon.shot_cooldown += 1.0
        case "camera":
            sim.state.camera_shake_pulses = 3
        case "inactive_creature":
            sim.creatures.entries[-1].hp = 17.0
        case "effect_allocator":
            sim.state.effects._free.reverse()
        case "mode_time":
            session.elapsed_ms = 10.0
        case "terrain_queue":
            session.terrain_fx.decals.entries[-1].rotation = 1.5
    assert session_digest(session) != before


def test_session_digest_ignores_paths_dirty_flags_profiling_and_rng_tracing() -> None:
    a, sim_a = make_session()
    b, sim_b = make_session()
    sim_a.state.status = GameStatus.from_data(path=Path("a/game.cfg"), data=GameStatusData(), dirty=True)
    sim_b.state.status = GameStatus.from_data(path=Path("b/game.cfg"), data=GameStatusData(), dirty=False)
    sim_b.state.rng = RecordingCrand(sim_b.state.rng)
    b.last_presentation_plan_ms = 99.0
    assert session_digest(a) == session_digest(b)


def test_session_digest_rejects_unrepresented_components(mocker) -> None:
    session, _sim = make_session()
    mocker.patch.object(session, "damage_scale_by_type", {1: object()})
    with pytest.raises(TypeError, match="unsupported deterministic state component"):
        session_digest(session)


def test_session_digest_is_independent_of_mapping_insertion_order() -> None:
    a, _ = make_session()
    b, _ = make_session()
    b.damage_scale_by_type = dict(reversed(list(a.damage_scale_by_type.items())))
    assert session_digest(a) == session_digest(b)
