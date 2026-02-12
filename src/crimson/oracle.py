"""Headless oracle mode for differential testing.

Runs the game simulation without rendering, accepts inputs from a JSON file,
and emits game state to stdout each frame for comparison with other implementations.
"""

from __future__ import annotations

from grim.geom import Vec2

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sim.input import PlayerInput
from .sim.state_types import PlayerState
from .sim.runners.common import build_damage_scale_by_type
from .sim.sessions import SurvivalDeterministicSession
from .sim.world_state import WorldState


class OutputMode:
    """Output modes for oracle state emission."""

    FULL = "full"  # Complete state every sample
    SUMMARY = "summary"  # Score, kills, player pos/health only
    HASH = "hash"  # SHA256 hash of full state for fast comparison
    CHECKPOINTS = "checkpoints"  # Only on significant events


@dataclass(frozen=True, slots=True)
class OracleConfig:
    """Configuration for headless oracle mode."""

    seed: int
    input_file: Path | None
    max_frames: int = 36000  # 10 minutes at 60fps
    frame_rate: int = 60
    sample_rate: int = 1  # Emit state every N frames (1 = every frame, 60 = once per second)
    output_mode: str = OutputMode.SUMMARY
    preserve_bugs: bool = False


@dataclass(slots=True)
class FrameInput:
    """Input for a single frame."""

    frame: int
    move: Vec2 = field(default_factory=Vec2)
    aim: Vec2 = field(default_factory=Vec2)
    fire_down: bool = False
    fire_pressed: bool = False
    reload_pressed: bool = False


def load_inputs(path: Path) -> list[FrameInput]:
    """Load input sequence from JSON file.

    Expected format:
    {
        "frames": [
            {"frame": 0, "move_x": 1.0, "move_y": 0.0, "aim": [100, 200], "fire_down": true},
            {"frame": 60, "move_x": 0.0, "move_y": -1.0, "fire_pressed": true},
            ...
        ]
    }
    """
    data = json.loads(path.read_text())
    inputs: list[FrameInput] = []
    for entry in data.get("frames", []):
        raw_aim = entry.get("aim", [0.0, 0.0])
        if not isinstance(raw_aim, list) or len(raw_aim) != 2:
            raise ValueError(f"frame {entry.get('frame', 0)} has invalid aim payload: expected [x, y]")
        inputs.append(
            FrameInput(
                frame=int(entry.get("frame", 0)),
                move=Vec2(float(entry.get("move_x", 0.0)), float(entry.get("move_y", 0.0))),
                aim=Vec2(float(raw_aim[0]), float(raw_aim[1])),
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
        "pos": player.pos.to_dict(ndigits=4),
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
        **creature.pos.to_dict(ndigits=4),
        "hp": round(float(creature.hp), 4),
        "active": bool(creature.active),
    }


def export_bonus_state(bonus: Any) -> dict[str, Any]:
    """Export bonus state to JSON-serializable dict."""
    return {
        "bonus_id": int(bonus.bonus_id),
        "pos": bonus.pos.to_dict(ndigits=4),
        "time_left": round(float(bonus.time_left), 4),
        "picked": bool(bonus.picked),
    }


def export_projectile_state(proj: Any) -> dict[str, Any]:
    """Export projectile state to JSON-serializable dict."""
    return {
        "type_id": int(proj.type_id),
        "x": round(proj.x, 4),
        "y": round(proj.y, 4),
        "active": bool(proj.active),
    }


def export_game_state_full(
    frame: int,
    world_state: WorldState,
    players: list[PlayerState],
    rng_state: int,
    elapsed_ms: float,
    command_hash: str,
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
        "command_hash": str(command_hash),
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


def export_game_state_summary(
    frame: int,
    world_state: WorldState,
    players: list[PlayerState],
    rng_state: int,
    elapsed_ms: float,
    command_hash: str,
) -> dict[str, Any]:
    """Export minimal game state for fast comparison."""
    total_experience = sum(p.experience for p in players)
    kill_count = world_state.creatures.kill_count
    creature_count = sum(1 for c in world_state.creatures.entries if c.active)

    return {
        "frame": frame,
        "rng_state": rng_state,
        "command_hash": str(command_hash),
        "elapsed_ms": round(elapsed_ms, 4),
        "score": int(total_experience),
        "kills": int(kill_count),
        "creature_count": creature_count,
        "players": [
            {
                "pos": p.pos.to_dict(ndigits=2),
                "health": round(float(p.health), 2),
                "weapon_id": int(p.weapon_id),
                "level": int(p.level),
            }
            for p in players
        ],
    }


def export_game_state_hash(
    frame: int,
    world_state: WorldState,
    players: list[PlayerState],
    rng_state: int,
    elapsed_ms: float,
    command_hash: str,
) -> dict[str, Any]:
    """Export hash of game state for ultra-fast comparison."""
    # Get full state and hash it
    full_state = export_game_state_full(frame, world_state, players, rng_state, elapsed_ms, command_hash)
    # Remove frame from hash computation (it's metadata)
    hashable = {k: v for k, v in full_state.items() if k != "frame"}
    state_bytes = json.dumps(hashable, sort_keys=True).encode()
    state_hash = hashlib.sha256(state_bytes).hexdigest()[:16]

    return {
        "frame": frame,
        "hash": state_hash,
        "command_hash": str(command_hash),
        "score": full_state["score"],
        "kills": full_state["kills"],
    }


@dataclass(slots=True)
class CheckpointTracker:
    """Track significant events for checkpoint-only output."""

    last_score: int = 0
    last_kills: int = 0
    last_level: int = 1
    last_health: float = 100.0
    last_weapon_id: int = 1

    def check_and_update(self, players: list[PlayerState], world_state: WorldState) -> bool:
        """Return True if any significant change occurred."""
        score = sum(p.experience for p in players)
        kills = world_state.creatures.kill_count
        level = players[0].level if players else 1
        health = players[0].health if players else 0.0
        weapon_id = players[0].weapon_id if players else 1

        changed = (
            score != self.last_score
            or kills != self.last_kills
            or level != self.last_level
            or int(health) != int(self.last_health)  # Only trigger on integer health change
            or weapon_id != self.last_weapon_id
        )

        if changed:
            self.last_score = score
            self.last_kills = kills
            self.last_level = level
            self.last_health = health
            self.last_weapon_id = weapon_id

        return changed


def run_headless(config: OracleConfig) -> None:
    """Run the game in headless mode, emitting state JSON each frame."""
    from .effects import FxQueue, FxQueueRotated

    # Build world state
    world_state = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=bool(config.preserve_bugs),
    )

    # Initialize with seed
    world_state.state.rng.srand(config.seed)

    # Set up player at center
    players = world_state.players
    if not players:
        from .sim.state_types import PlayerState
        from .weapon_runtime import weapon_assign_player

        player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
        weapon_assign_player(player, 1)
        players.append(player)

    # Load inputs if provided
    inputs_by_frame: dict[int, FrameInput] = {}
    if config.input_file is not None:
        for inp in load_inputs(config.input_file):
            inputs_by_frame[inp.frame] = inp

    dt = 1.0 / float(config.frame_rate)
    current_input = FrameInput(frame=0)

    # Headless deterministic step still routes through sim/presentation queues.
    fx_queue = FxQueue()
    fx_queue_rotated = FxQueueRotated()
    session = SurvivalDeterministicSession(
        world=world_state,
        world_size=1024.0,
        damage_scale_by_type=build_damage_scale_by_type(),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=5,
        fx_toggle=0,
        game_tune_started=False,
        auto_pick_perks=True,
        demo_mode_active=False,
        perk_progression_enabled=True,
        clear_fx_queues_each_tick=True,
    )
    last_command_hash = ""

    # Checkpoint tracker for event-driven output
    checkpoint_tracker = CheckpointTracker()

    # Select export function based on output mode
    export_fn = {
        OutputMode.FULL: export_game_state_full,
        OutputMode.SUMMARY: export_game_state_summary,
        OutputMode.HASH: export_game_state_hash,
        OutputMode.CHECKPOINTS: export_game_state_summary,  # Same format, different trigger
    }.get(config.output_mode, export_game_state_summary)

    for frame in range(config.max_frames):
        # Update current input if we have one for this frame
        if frame in inputs_by_frame:
            current_input = inputs_by_frame[frame]

        # Convert to PlayerInput
        player_inputs = [
            PlayerInput(
                move=current_input.move,
                aim=current_input.aim,
                fire_down=current_input.fire_down,
                fire_pressed=current_input.fire_pressed,
                reload_pressed=current_input.reload_pressed,
            )
        ]

        tick = session.step_tick(dt_frame=dt, inputs=player_inputs)
        last_command_hash = str(tick.step.command_hash)
        elapsed_ms = float(session.elapsed_ms)

        # Determine if we should emit state this frame
        should_emit = False
        if config.output_mode == OutputMode.CHECKPOINTS:
            # Only emit on significant changes
            should_emit = checkpoint_tracker.check_and_update(players, world_state)
            # Always emit first and last frame
            if frame == 0:
                should_emit = True
        else:
            # Sample rate based emission
            should_emit = frame % config.sample_rate == 0

        if should_emit:
            state_json = export_fn(
                frame=frame,
                world_state=world_state,
                players=players,
                rng_state=world_state.state.rng.state,
                elapsed_ms=elapsed_ms,
                command_hash=str(last_command_hash),
            )
            print(json.dumps(state_json), flush=True)

        # Check if all players dead
        if all(p.health <= 0 for p in players):
            # Always emit final state on death
            if not should_emit:
                state_json = export_fn(
                    frame=frame,
                    world_state=world_state,
                    players=players,
                    rng_state=world_state.state.rng.state,
                    elapsed_ms=elapsed_ms,
                    command_hash=str(last_command_hash),
                )
                print(json.dumps(state_json), flush=True)
            break
