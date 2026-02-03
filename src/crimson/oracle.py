"""Headless oracle mode for differential testing.

Runs the game simulation without rendering, accepts inputs from a JSON file,
and emits game state to stdout each frame for comparison with other implementations.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .gameplay import GameplayState, PlayerInput, PlayerState
from .creatures.runtime import CreaturePool
from .bonuses import BonusId
from .sim.world_state import WorldState


@dataclass(frozen=True, slots=True)
class OracleConfig:
    """Configuration for headless oracle mode."""

    seed: int
    input_file: Path | None
    max_frames: int = 36000  # 10 minutes at 60fps
    frame_rate: int = 60


@dataclass(slots=True)
class FrameInput:
    """Input for a single frame."""

    frame: int
    move_x: float = 0.0
    move_y: float = 0.0
    aim_x: float = 0.0
    aim_y: float = 0.0
    fire_down: bool = False
    fire_pressed: bool = False
    reload_pressed: bool = False


def load_inputs(path: Path) -> list[FrameInput]:
    """Load input sequence from JSON file.

    Expected format:
    {
        "frames": [
            {"frame": 0, "move_x": 1.0, "move_y": 0.0, "aim_x": 100, "aim_y": 200, "fire_down": true},
            {"frame": 60, "move_x": 0.0, "move_y": -1.0, "fire_pressed": true},
            ...
        ]
    }
    """
    data = json.loads(path.read_text())
    inputs: list[FrameInput] = []
    for entry in data.get("frames", []):
        inputs.append(
            FrameInput(
                frame=int(entry.get("frame", 0)),
                move_x=float(entry.get("move_x", 0.0)),
                move_y=float(entry.get("move_y", 0.0)),
                aim_x=float(entry.get("aim_x", 0.0)),
                aim_y=float(entry.get("aim_y", 0.0)),
                fire_down=bool(entry.get("fire_down", False)),
                fire_pressed=bool(entry.get("fire_pressed", False)),
                reload_pressed=bool(entry.get("reload_pressed", False)),
            )
        )
    return sorted(inputs, key=lambda i: i.frame)


def export_player_state(player: PlayerState) -> dict[str, Any]:
    """Export player state to JSON-serializable dict."""
    return {
        "index": int(player.index),
        "pos_x": round(float(player.pos_x), 4),
        "pos_y": round(float(player.pos_y), 4),
        "health": round(float(player.health), 4),
        "weapon_id": int(player.weapon_id),
        "ammo": round(float(player.ammo), 4),
        "experience": int(player.experience),
        "level": int(player.level),
        "reload_active": bool(player.reload_active),
        "heading": round(float(player.heading), 4),
        "aim_heading": round(float(player.aim_heading), 4),
    }


def export_creature_state(creature: Any) -> dict[str, Any]:
    """Export creature state to JSON-serializable dict."""
    return {
        "id": int(creature.id) if hasattr(creature, "id") else -1,
        "type_id": int(creature.type_id),
        "x": round(float(creature.x), 4),
        "y": round(float(creature.y), 4),
        "hp": round(float(creature.hp), 4),
        "active": bool(creature.active),
    }


def export_bonus_state(bonus: Any) -> dict[str, Any]:
    """Export bonus state to JSON-serializable dict."""
    return {
        "bonus_id": int(bonus.bonus_id),
        "pos_x": round(float(bonus.pos_x), 4),
        "pos_y": round(float(bonus.pos_y), 4),
        "time_left": round(float(bonus.time_left), 4),
        "picked": bool(bonus.picked),
    }


def export_projectile_state(proj: Any) -> dict[str, Any]:
    """Export projectile state to JSON-serializable dict."""
    return {
        "type_id": int(proj.type_id),
        "x": round(float(proj.x), 4),
        "y": round(float(proj.y), 4),
        "active": bool(proj.active),
    }


def export_game_state(
    frame: int,
    world_state: WorldState,
    players: list[PlayerState],
    rng_state: int,
    elapsed_ms: float,
) -> dict[str, Any]:
    """Export complete game state for a frame."""
    state = world_state.state

    # Collect active creatures
    creatures = []
    for creature in world_state.creatures.entries:
        if creature.active:
            creatures.append(export_creature_state(creature))

    # Collect active bonuses
    bonuses = []
    for bonus in state.bonus_pool.iter_active():
        bonuses.append(export_bonus_state(bonus))

    # Collect active projectiles
    projectiles = []
    for proj in state.projectiles.entries:
        if proj.active:
            projectiles.append(export_projectile_state(proj))

    # Score is player experience, kills tracked on creatures pool
    total_experience = sum(p.experience for p in players)
    kill_count = world_state.creatures.kill_count

    return {
        "frame": frame,
        "rng_state": rng_state,
        "elapsed_ms": round(elapsed_ms, 4),
        "score": int(total_experience),
        "kills": int(kill_count),
        "players": [export_player_state(p) for p in players],
        "creatures": creatures,
        "bonuses": bonuses,
        "projectiles": projectiles,
        "bonus_timers": {
            "weapon_power_up": round(float(state.bonuses.weapon_power_up), 4),
            "reflex_boost": round(float(state.bonuses.reflex_boost), 4),
            "freeze": round(float(state.bonuses.freeze), 4),
        },
    }


def run_headless(config: OracleConfig) -> None:
    """Run the game in headless mode, emitting state JSON each frame."""
    from .sim.world_state import WorldState
    from .effects import FxQueue, FxQueueRotated
    from .game_modes import GameMode

    # Build world state
    world_state = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )

    # Initialize with seed
    world_state.state.rng.srand(config.seed)

    # Set up player at center
    players = world_state.players
    if not players:
        from .gameplay import PlayerState, weapon_assign_player

        player = PlayerState(index=0, pos_x=512.0, pos_y=512.0)
        weapon_assign_player(player, 1)
        players.append(player)

    # Load inputs if provided
    inputs_by_frame: dict[int, FrameInput] = {}
    if config.input_file is not None:
        for inp in load_inputs(config.input_file):
            inputs_by_frame[inp.frame] = inp

    dt = 1.0 / float(config.frame_rate)
    current_input = FrameInput(frame=0)
    elapsed_ms = 0.0

    # Create dummy FX queues (not used in headless mode)
    fx_queue = FxQueue()
    fx_queue_rotated = FxQueueRotated()

    for frame in range(config.max_frames):
        # Update current input if we have one for this frame
        if frame in inputs_by_frame:
            current_input = inputs_by_frame[frame]

        # Convert to PlayerInput
        player_inputs = [
            PlayerInput(
                move_x=current_input.move_x,
                move_y=current_input.move_y,
                aim_x=current_input.aim_x,
                aim_y=current_input.aim_y,
                fire_down=current_input.fire_down,
                fire_pressed=current_input.fire_pressed,
                reload_pressed=current_input.reload_pressed,
            )
        ]

        # Step simulation
        world_state.step(
            dt,
            inputs=player_inputs,
            world_size=1024.0,
            damage_scale_by_type={},
            detail_preset=5,
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            auto_pick_perks=True,
            game_mode=int(GameMode.SURVIVAL),
            perk_progression_enabled=True,
        )

        elapsed_ms += dt * 1000.0

        # Export and emit state
        state_json = export_game_state(
            frame=frame,
            world_state=world_state,
            players=players,
            rng_state=world_state.state.rng.state,
            elapsed_ms=elapsed_ms,
        )
        print(json.dumps(state_json), flush=True)

        # Check if all players dead
        if all(p.health <= 0 for p in players):
            break
