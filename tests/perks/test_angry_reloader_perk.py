from __future__ import annotations

import pytest

from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from grim.geom import Vec2
from grim.rand import RecordingCrand
from grim.sfx_map import SfxId
from tests.support.factories import player_input, step_player
from tests.support.helpers import assert_rng_progression


@pytest.mark.parametrize(("cl_build", "ring"), [(ClBuild.V1_9_93, 0), (ClBuild.V1_9_8, 8)])
def test_angry_reloader_rings_a_short_reload_only_in_1_9_8(cl_build: ClBuild, ring: int) -> None:
    # A 0.4 s reload is under 1.9.93's 0.5 s gate; 1.9.8 has none and fires `7 + (int)(0.4 * 4)` shots
    # as the timer crosses half.
    world = initialize_run(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=7, cl_build=cl_build)).session.world
    world.state.perks[PerkId.ANGRY_RELOADER] = 1
    player = world.players[0]
    player.weapon.reload_active = True
    player.weapon.reload_timer_max = f32(0.4)
    player.weapon.reload_timer = f32(0.21)
    rng = RecordingCrand(world.state.rng)
    world.state.rng = rng
    before_state = rng.state

    step_player(world, player, player_input(aim=Vec2(1.0, 0.0)), 0.05)

    shots = [
        projectile
        for projectile in world.state.projectiles.entries
        if projectile.active and projectile.type_id == ProjectileTemplateId.PLASMA_MINIGUN
    ]
    assert len(shots) == ring
    assert [request.sfx_id for request in world.state.sfx_queue] == [SfxId.EXPLOSION_SMALL] * bool(ring)
    # The ring is a scripted burst: it draws nothing.
    assert_rng_progression(rng, before_calls=0, before_state=before_state, expected_draws=0)
