"""Deterministic scripted gameplay fixtures for the RTX frame benchmark."""

from __future__ import annotations

import math
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
SOURCE_COMMIT = subprocess.check_output(
    [shutil.which("git") or "/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
).strip()
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
import msgspec

from crimson.bonuses.ids import BonusId
from crimson.creatures.spawn import CreatureTypeId
from crimson.perks import PerkId
from crimson.sim.batch_apply import apply_presentation_plans
from crimson.sim.clock import PresentationClock
from crimson.sim.sessions import DeterministicSession
from crimson.weapon_runtime.assign import weapon_assign_player
from crimson.weapons import WeaponId
from grim.color import RGBA
from grim.geom import Vec2
from tests.support.factories import make_creature_state, player_input

OUT = Path(__file__).resolve().parent
SCENES = {"launcher": 12, "seeker": 13, "swarmers": 17, "minigun": 18, "nuke": 1, "dense": 17}
NAMES = {
    "launcher": "Rocket Launcher",
    "seeker": "Seeker Rockets",
    "swarmers": "Rocket Swarmers",
    "minigun": "Rocket Minigun",
    "nuke": "Nuke pickup / 15-second smoke",
}
FPS, W, H = 30, 640, 480
CAMERA = Vec2(-192, -272)


class Scene:
    def __init__(self, runtime, name, *, perks=False):
        self.runtime, self.name, self.tick = runtime, name, 0
        self.perks = perks
        runtime.reset(seed=0x51A07, player_count=2)
        runtime.presentation = PresentationClock()
        world = runtime.world
        world.state.detail_preset = 5
        world.state.game_tune_started = True
        self.session = DeterministicSession.start(world, perk_progression_enabled=False)
        runtime.start_session(self.session)
        if perks:
            world.state.perks[PerkId.RADIOACTIVE] = 1
            world.state.perks[PerkId.MONSTER_VISION] = 1
        p, light = world.players
        p.pos = Vec2(512, 512) if name == "nuke" else Vec2(350, 480)
        light.pos = Vec2(350, 560)
        for player in world.players:
            player.health = 1000
            player.heading = player.aim_heading = math.pi / 2
        weapon_assign_player(p, WeaponId(SCENES[name]), state=world.state)
        weapon_assign_player(light, WeaponId.ASSAULT_RIFLE, state=world.state)
        target = make_creature_state(pos=Vec2(665, 495), hp=50000, size=50)
        target.move_speed = 0
        target.contact_damage = 0
        target.tint = RGBA(0.65, 0.85, 0.7, 1)
        world.creatures.entries[0] = target
        for i, (x, y, kind) in enumerate(((420, 410, CreatureTypeId.SPIDER_SP1), (680, 600, CreatureTypeId.LIZARD)), 1):
            creature = make_creature_state(pos=Vec2(x, y), hp=50000, size=45, type_id=kind)
            creature.move_speed = 0
            creature.contact_damage = 0
            world.creatures.entries[i] = creature
        self.events, self.rows = [], []

    def advance(self, t, *, present):
        world = self.runtime.world
        while self.tick < round(t * 60):
            tick = self.tick
            now = tick / 60
            player, light = world.players
            if self.name == "nuke" and tick == 30:
                world.state.bonus_pool.spawn_at(player.pos, BonusId.NUKE, state=world.state)
            if tick == 144:
                weapon_assign_player(light, WeaponId.ASSAULT_RIFLE, state=world.state)
                light.fire_bullets_timer = 1.2
            if tick == 264:
                weapon_assign_player(light, WeaponId.ION_RIFLE, state=world.state)
                light.fire_bullets_timer = 0
            light_fire = any(start <= tick < start + 12 for start in (144, 264))
            world.state.perks[PerkId.SHARPSHOOTER] = int(2 <= now < 14.5)
            sweep = 30 * math.sin((now - 2) * 1.9) if now > 2 else 0
            inputs = [
                player_input(
                    aim=Vec2(665, 495 + sweep),
                    fire_down=self.name != "nuke" and 30 <= tick < 240,
                    move=Vec2(-1, 0) if self.name == "nuke" and 31 <= tick < 100 else Vec2(),
                ),
                player_input(aim=Vec2(690, 450 + 20 * math.sin(now)), fire_down=light_fire),
            ]
            step = self.session.step_tick(dt=1 / 60, inputs=inputs)
            self.runtime.presentation.advance(step.dt_sim)
            for event in step.presentation.smoke_emissions:
                self.events.append({"time": now, **msgspec.to_builtins(event)})
            if present:
                apply_presentation_plans(plans=(step.presentation,), runtime=self.runtime)
            self.tick += 1
        self.runtime.camera = CAMERA
        smoke = self.runtime.render_resources.smoke.simulation
        row = {
            "time": t,
            "fields": len(smoke.fields),
            "shots_fired": world.state.shots_fired,
            "active_secondary": sum(e.active for e in world.state.secondary_projectiles.entries),
            "executed_steps": getattr(smoke, "executed_steps", None),
        }
        self.rows.append(row)
        return row

    def proof(self):
        return {
            "scene": self.name,
            "weapon_id": SCENES[self.name],
            "seed": 0x51A07,
            "source_commit": SOURCE_COMMIT,
            "radioactive_and_monster_vision": self.perks,
            "source": "Scripted native session inputs and actual bonus pickup; stationary native target fixtures.",
            "weapon_shots_fired": self.runtime.world.state.weapon_shots_fired,
            "events": self.events,
            "frames": self.rows,
        }
