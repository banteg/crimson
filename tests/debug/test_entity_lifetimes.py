from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureTypeId, creature_spawn
from crimson.game_modes import GameMode
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.projectiles.runtime import (
    ProjectilePool,
    SecondaryProjectilePool,
    fx_spawn_secondary_projectile,
    projectile_spawn,
)
from crimson.projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson_re.dbg.record import _entity_samples_for_world
from grim.color import RGBA
from grim.geom import Vec2
from tests.replay.cli._helpers import build_replay


def test_entity_uids_follow_allocations_between_snapshots() -> None:
    world = build_verify_playback_driver(build_replay(mode=GameMode.SURVIVAL, ticks=1)).world
    world.creatures = CreaturePool()
    world.state.projectiles = ProjectilePool()
    world.state.secondary_projectiles = SecondaryProjectilePool()
    world.state.bonus_pool = BonusPool()
    # Leave only the last projectile slot free so the second round finds both pools full.
    for projectile_pool in (world.state.projectiles, world.state.secondary_projectiles):
        for entry in projectile_pool.entries[:-1]:
            entry.active = True

    def spawn_all() -> None:
        creature_spawn(world.creatures, Vec2(), RGBA(), CreatureTypeId.ALIEN, world.state.rng, survival_elapsed_ms=0)
        projectile_spawn(
            world.state,
            players=world.players,
            pos=Vec2(),
            angle=0.0,
            type_id=ProjectileTemplateId.PISTOL,
            owner_id=OWNER_LOCAL_PLAYER,
            owner_player_index=0,
        )
        fx_spawn_secondary_projectile(
            world.state,
            world.players[0],
            world.creatures.entries,
            pos=Vec2(),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.ROCKET,
        )
        world.state.bonus_pool.spawn_at(Vec2(), BonusId.POINTS, state=world.state)

    spawn_all()
    first = _entity_samples_for_world(world)
    # Neither retirement nor intermediate allocation is observed by the recorder.
    world.creatures.entries[0].active = False
    world.state.bonus_pool.entries[0].bonus_id = BonusId.UNUSED
    spawn_all()  # Full projectile pools overwrite an active slot.
    second = _entity_samples_for_world(world)
    for name in ["creatures", "projectiles", "secondary_projectiles", "bonuses"]:
        before, after = getattr(first, name)[-1], getattr(second, name)[-1]
        assert (before.generation, after.generation) == (1, 2)
        assert before.uid != after.uid
    assert _entity_samples_for_world(world) == second


def test_frida_allocation_hooks_track_reuse_and_skip_sentinels() -> None:
    import shutil
    import subprocess
    from pathlib import Path

    import pytest

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to exercise Frida JavaScript without injecting a process")
    source = (Path(__file__).parents[2] / "scripts/frida/gameplay_diff_capture.js").read_text()
    uid_functions = source[source.index("function newEntityUidState()") : source.index("function questLevelKey(")]
    hook_start = source.index("  // Count materializations")
    hooks = source[hook_start : source.index('  attachHook("secondary_projectile_spawn"', hook_start)]
    harness = '''
const assert = require("node:assert/strict");
const outState = {};
const installed = {};
const fnPtrs = {};
const dataPtrs = {bonus_pool: 0x482948};
const STRIDES = {bonus: 0x1c};
const COUNTS = {creatures: 384, bonuses: 16};
function failCaptureContract(message) { throw new Error(message); }
function attachHook(name, address, handlers) { installed[name] = handlers; }
function pointer(value) { return {toInt32: () => value, sub: (other) => pointer(value - other)}; }
'''
    checks = '''
installed.creature_alloc_slot.onLeave(pointer(0));
assert.equal(nextEntityUid("creature", 0).generation, 1);
installed.creature_alloc_slot.onLeave(pointer(0));
assert.equal(nextEntityUid("creature", 0).generation, 2);
assert.equal(nextEntityUid("creature", 0).generation, 2);
installed.creature_alloc_slot.onLeave(pointer(384));
assert.equal(outState.entityUidStates.creature.generationByIndex[384], undefined);
installed.bonus_spawn_at.onLeave(pointer(dataPtrs.bonus_pool));
installed.bonus_spawn_at_pos.onLeave(pointer(dataPtrs.bonus_pool));
assert.equal(nextEntityUid("bonus", 0).generation, 2);
installed.bonus_spawn_at_pos.onLeave(pointer(dataPtrs.bonus_pool + 16 * STRIDES.bonus));
assert.equal(outState.entityUidStates.bonus.generationByIndex[16], undefined);
resetEntityUidStates();
assert.throws(() => nextEntityUid("creature", 0));
'''
    result = subprocess.run([node, "-e", harness + uid_functions + hooks + checks], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
