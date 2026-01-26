from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache
from grim.config import CrimsonConfig

from .creatures.runtime import CreaturePool
from .creatures.spawn import SpawnEnv
from .gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_update,
    player_update,
    survival_progression_update,
    weapon_assign_player,
)
from .weapons import WEAPON_TABLE

GAME_MODE_SURVIVAL = 3


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


ProjectileHit = tuple[int, float, float, float, float]


@dataclass(slots=True)
class GameWorld:
    assets_dir: Path
    world_size: float = 1024.0
    demo_mode_active: bool = False
    difficulty_level: int = 0
    hardcore: bool = False
    texture_cache: PaqTextureCache | None = None
    config: CrimsonConfig | None = None

    spawn_env: SpawnEnv = field(init=False)
    state: GameplayState = field(init=False)
    players: list[PlayerState] = field(init=False)
    creatures: CreaturePool = field(init=False)
    camera_x: float = field(init=False, default=-1.0)
    camera_y: float = field(init=False, default=-1.0)
    _damage_scale_by_type: dict[int, float] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.spawn_env = SpawnEnv(
            terrain_width=float(self.world_size),
            terrain_height=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            difficulty_level=int(self.difficulty_level),
        )
        self.state = GameplayState()
        self.players: list[PlayerState] = []
        self.creatures = CreaturePool(env=self.spawn_env)
        self.camera_x = -1.0
        self.camera_y = -1.0
        self._damage_scale_by_type = {
            entry.weapon_id: float(entry.damage_mult or 1.0)
            for entry in WEAPON_TABLE
            if entry.weapon_id >= 0
        }
        self.reset()

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
        spawn_x: float | None = None,
        spawn_y: float | None = None,
    ) -> None:
        self.state = GameplayState()
        self.state.rng.srand(int(seed))
        self.creatures = CreaturePool(env=self.spawn_env)
        self.players = []
        base_x = float(self.world_size) * 0.5 if spawn_x is None else float(spawn_x)
        base_y = float(self.world_size) * 0.5 if spawn_y is None else float(spawn_y)
        for idx in range(max(1, int(player_count))):
            player = PlayerState(index=idx, pos_x=base_x, pos_y=base_y)
            weapon_assign_player(player, 0)
            self.players.append(player)
        self.camera_x = -1.0
        self.camera_y = -1.0

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def update(
        self,
        dt: float,
        *,
        inputs: list[PlayerInput] | None = None,
        auto_pick_perks: bool = False,
        game_mode: int = GAME_MODE_SURVIVAL,
    ) -> list[ProjectileHit]:
        if inputs is None:
            inputs = [PlayerInput() for _ in self.players]

        hits = self.state.projectiles.update(
            dt,
            self.creatures.entries,
            world_size=float(self.world_size),
            damage_scale_by_type=self._damage_scale_by_type,
            rng=self.state.rng.rand,
            runtime_state=self.state,
        )
        self.state.secondary_projectiles.update_pulse_gun(dt, self.creatures.entries)

        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player_update(player, input_state, dt, self.state, world_size=float(self.world_size))

        self.creatures.update(
            dt,
            state=self.state,
            players=self.players,
            world_width=float(self.world_size),
            world_height=float(self.world_size),
        )

        bonus_update(self.state, self.players, dt, creatures=self.creatures.entries, update_hud=True)

        if game_mode == GAME_MODE_SURVIVAL:
            survival_progression_update(self.state, self.players, game_mode=game_mode, auto_pick=auto_pick_perks)

        self.update_camera(dt)
        return hits

    def update_camera(self, dt: float) -> None:
        if not self.players:
            return
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        if screen_w > self.world_size:
            screen_w = float(self.world_size)
        if screen_h > self.world_size:
            screen_h = float(self.world_size)

        focus = self.players[0]
        desired_x = (screen_w * 0.5) - focus.pos_x
        desired_y = (screen_h * 0.5) - focus.pos_y

        min_x = screen_w - float(self.world_size)
        min_y = screen_h - float(self.world_size)
        desired_x = _clamp(desired_x, min_x, -1.0)
        desired_y = _clamp(desired_y, min_y, -1.0)

        t = _clamp(dt * 6.0, 0.0, 1.0)
        self.camera_x = _lerp(self.camera_x, desired_x, t)
        self.camera_y = _lerp(self.camera_y, desired_y, t)

    def world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        return self.camera_x + x, self.camera_y + y

    def screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        return x - self.camera_x, y - self.camera_y
