"""Measure crowded gameplay cases on the Python port. Run as python -m scripts.bench_gameplay_bursts."""

from __future__ import annotations

import argparse
import cProfile
import math
import statistics
from collections.abc import Callable
from functools import partial
from pathlib import Path
from time import perf_counter_ns

from crimson.bonuses.apply import bonus_apply
from crimson.bonuses.ids import BonusId
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn_ids import SpawnId
from crimson.game_modes import GameMode
from crimson.perks import PERK_BY_ID, PerkFlags, PerkId
from crimson.perks.selection import perk_generate_choices
from crimson.projectiles.types import ProjectileTemplateId
from crimson.render.ion_arcs import ion_arcs_drawn
from crimson.render.rtx.material_lights import collect_material_lights, ion_contact_glows
from crimson.replay import load_replay_file
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.render.test_material_lights import frame
from tests.support.factories import fire_player_weapon, make_step_runtime, player_input, world_with_creature

DT = 1 / 60
ORIGIN = Vec2(512, 512)
Operation = Callable[[], object]


def volley(weapon: WeaponId, creatures: int, spacing: float) -> Operation:
    world = world_with_creature(CreatureState())
    state = world.state
    state.detail_preset = 5
    runtime = make_step_runtime(world, dt=DT)
    player = world.players[0]
    player.pos = Vec2(496, 514)
    player.aim_heading = math.pi / 2
    player.spread_heat = 0.01
    gauss = weapon == WeaponId.GAUSS_SHOTGUN
    for i, target in enumerate(world.creatures.entries[:creatures]):
        target.active = True
        target.hp = target.max_hp = target.reward_value = 100.0
        target.size = 46.0
        if gauss:
            target.pos = Vec2(532 + (i % 16) * 2, 545 + (i // 16) * 0.5 + spacing)
        else:
            target.pos = ORIGIN + Vec2(i % 16, i // 16 - creatures // 32) * spacing
    if gauss:
        state.perks[PerkId.BARREL_GREASER] = 1
    weapon_assign_player(player, weapon, state=state)
    state.rng.srand(97)
    fire_player_weapon(world, player, player_input(fire_down=True, aim=Vec2(900, 514)), DT, step_runtime=runtime)

    def step():
        hits = state.projectiles.step(runtime)
        return len(hits), len(runtime.deaths), len(state.projectiles.iter_active())

    return step


def ion_frame(count: int, offset_y: float) -> Operation:
    scene = frame()
    for i, target in enumerate(scene.creatures.entries[:count]):
        target.active = True
        target.size = 46.0
        target.pos = ORIGIN + Vec2(1 + i % 16, 1 + i // 16 + offset_y)
    pellets = scene.state.projectiles.entries[:8]
    for i, pellet in enumerate(pellets):
        pellet.active = True
        pellet.type_id = ProjectileTemplateId.ION_MINIGUN
        pellet.pos = ORIGIN + Vec2(i, 0)
        pellet.origin = Vec2(425, 510)
        pellet.life_timer = 0.25

    def prepare():
        lights = collect_material_lights(scene, view_center=ORIGIN, view_size=Vec2(1024, 768))
        glows = ion_contact_glows(scene, view_center=ORIGIN)
        arcs = sum(1 for pellet in pellets for _ in ion_arcs_drawn(scene, pellet))
        return len(lights), len(glows), arcs

    return prepare


def perk_menu(owned: int) -> Operation:
    world = world_with_creature(CreatureState())
    world.players.append(PlayerState(index=1, pos=Vec2(600, 600)))
    state = world.state
    single_picks = [
        perk
        for perk, meta in PERK_BY_ID.items()
        if state.perk_available[perk]
        and meta.flags & PerkFlags.MULTIPLAYER_ALLOWED
        and not meta.flags & PerkFlags.STACKABLE
    ]
    for perk in single_picks[:owned]:
        state.perks[perk] = 1
    state.rng.srand(97)
    return lambda: tuple(int(p) for p in perk_generate_choices(state, world.players, game_mode=GameMode.SURVIVAL))


def nuke(roots: int) -> Operation:
    world = world_with_creature(CreatureState())
    state = world.state
    state.rng.srand(97)
    state.detail_preset = 5
    runtime = make_step_runtime(world, dt=DT)
    for i in range(roots):
        world.creatures.spawn_template(
            SpawnId.SPIDER_SP2_SPLITTER_01, ORIGIN + Vec2(i * 20, 0), 0, state=state, detail_preset=5,
        )

    def detonate():
        bonus_apply(
            state,
            world.players[0],
            BonusId.NUKE,
            amount=1,
            origin=ORIGIN,
            creatures=world.creatures.entries,
            players=world.players,
            step_runtime=runtime,
        )
        return len(runtime.deaths), world.players[0].experience

    return detonate


def recorded_tick() -> Callable[[], Operation]:
    path = Path(__file__).resolve().parents[1] / "tests/fixtures/replays/survival-238852.crd"
    driver = PlaybackDriver(load_replay_file(path), warn_on_version_mismatch=False)
    tick = 34680
    driver.walk_ticks(stop_tick=tick)
    before = driver.keyframe_state()

    def prepare() -> Operation:
        driver.restore(before)
        return lambda: len(driver.step_tick(tick).payload.events.deaths)

    return prepare


def measure(name: str, setup: Callable[[], Operation]) -> None:
    timings = []
    for _ in range(14):
        operation = setup()
        start = perf_counter_ns()
        result = operation()
        timings.append((perf_counter_ns() - start) / 1e6)

    profile = cProfile.Profile()
    if profile.runcall(setup()) != result:
        raise RuntimeError(f"{name} differed between the timed and profiled runs")
    counters = {
        "within_native_find_radius",
        "candidate_indices",
        "projectile_spawn",
        "rank",
        "rand_tagged",
        "handle_death",
    }
    counts = {
        s.code.co_name: s.callcount
        for s in profile.getstats()
        if not isinstance(s.code, str) and s.code.co_name in counters
    }
    print(f"{name}: {statistics.median(timings[1:]):.2f} ms, result={result}, calls={counts}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", action="store_true", help="also replay Survival to the recorded Final Revenge tick")
    args = parser.parse_args()
    for count in (96, 384):
        for offset in (0, 240):
            measure(f"Gauss / {count} targets / shift {offset}", partial(volley, WeaponId.GAUSS_SHOTGUN, count, offset))
    for gap in (3, 12):
        measure(f"Splitter / 16 targets / spacing {gap}", partial(volley, WeaponId.SPLITTER_GUN, 16, gap))
    for offset in (0, 200):
        measure(f"RTX ion / 384 targets / shift {offset}", partial(ion_frame, 384, offset))
    for count in (0, 21, 25):
        measure(f"Co-op perk menu / {count} owned", partial(perk_menu, count))
    for roots in (0, 1, 3):
        measure(f"Nuke / {roots} splitter roots", partial(nuke, roots))
    if args.replay:
        measure("Survival 238852 / tick 34680", recorded_tick())
