from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from grim.view import ViewContext

from ..creatures.spawn import advance_survival_spawn_stage, tick_rush_mode_spawns, tick_survival_wave_spawns
from ..game_modes import GameMode
from ..game_world import GameWorld
from ..gameplay import (
    PlayerInput,
    perk_selection_pick,
    perks_rebuild_available,
    weapon_assign_player,
    weapon_refresh_available,
)
from ..replay import PerkPickEvent, Replay, UnknownEvent, load_replay_file, unpack_input_flags, warn_on_game_version_mismatch
from ..sim.runners.common import build_damage_scale_by_type, status_from_snapshot, time_scale_reflex_boost_bonus

RUSH_WEAPON_ID = 2


@dataclass(slots=True)
class _SurvivalPlaybackState:
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown_ms: float = 0.0


@dataclass(slots=True)
class _RushPlaybackState:
    elapsed_ms: float = 0.0
    spawn_cooldown_ms: float = 0.0


class ReplayPlaybackMode:
    def __init__(self, ctx: ViewContext, *, replay_path: Path) -> None:
        self._ctx = ctx
        self._replay_path = Path(replay_path)

        self.close_requested = False

        self._replay: Replay | None = None
        self._world: GameWorld | None = None
        self._events_by_tick: dict[int, list[object]] = {}
        self._damage_scale_by_type = build_damage_scale_by_type()

        self._tick_rate = 60
        self._dt_frame = 1.0 / 60.0
        self._dt_accum = 0.0
        self._tick_index = 0
        self._finished = False

        self._survival: _SurvivalPlaybackState | None = None
        self._rush: _RushPlaybackState | None = None

    def open(self) -> None:
        replay = load_replay_file(self._replay_path)
        self._replay = replay
        warn_on_game_version_mismatch(replay, action="playback")

        tick_rate = int(replay.header.tick_rate)
        if tick_rate <= 0:
            raise ValueError(f"invalid tick_rate: {tick_rate}")
        self._tick_rate = tick_rate
        self._dt_frame = 1.0 / float(tick_rate)
        self._dt_accum = 0.0
        self._tick_index = 0
        self._finished = False

        events_by_tick: dict[int, list[object]] = {}
        for event in replay.events:
            events_by_tick.setdefault(int(event.tick_index), []).append(event)
        self._events_by_tick = events_by_tick

        world_size = float(replay.header.world_size)
        world = GameWorld(
            assets_dir=self._ctx.assets_dir,
            world_size=world_size,
            demo_mode_active=False,
            difficulty_level=int(replay.header.difficulty_level),
            hardcore=bool(replay.header.hardcore),
            preserve_bugs=bool(replay.header.preserve_bugs),
            texture_cache=None,
            config=None,
            audio=None,
            audio_rng=None,
        )
        world.reset(seed=0xBEEF, player_count=int(replay.header.player_count))
        world.open()
        world.state.status = status_from_snapshot(
            quest_unlock_index=int(replay.header.status.quest_unlock_index),
            quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        )
        # Important: `GameWorld.open()` consumes RNG for terrain generation. Treat `replay.header.seed` as the
        # gameplay RNG state at tick 0 and set it after `open()` to keep headless verification deterministic.
        world.state.rng.srand(int(replay.header.seed))

        self._world = world

        if int(replay.header.game_mode_id) == int(GameMode.SURVIVAL):
            self._survival = _SurvivalPlaybackState()
            self._rush = None
        elif int(replay.header.game_mode_id) == int(GameMode.RUSH):
            if replay.events:
                raise ValueError("rush replay does not support events")
            self._survival = None
            self._rush = _RushPlaybackState()
            self._enforce_rush_loadout()
        else:
            raise ValueError(f"unsupported replay game_mode_id: {int(replay.header.game_mode_id)}")

    def close(self) -> None:
        world = self._world
        self._world = None
        if world is not None:
            world.close()

    def _enforce_rush_loadout(self) -> None:
        world = self._world
        if world is None:
            return
        for player in world.players:
            if int(player.weapon_id) != int(RUSH_WEAPON_ID):
                weapon_assign_player(player, int(RUSH_WEAPON_ID))
            player.ammo = float(max(0, int(player.clip_size)))

    def _apply_tick_events(self, *, tick_index: int, dt_frame: float) -> None:
        replay = self._replay
        world = self._world
        if replay is None or world is None:
            return
        for event in self._events_by_tick.get(int(tick_index), []):
            if isinstance(event, PerkPickEvent):
                picked = perk_selection_pick(
                    world.state,
                    world.players,
                    world.state.perk_selection,
                    int(event.choice_index),
                    game_mode=int(replay.header.game_mode_id),
                    player_count=len(world.players),
                    dt=float(dt_frame),
                    creatures=world.creatures.entries,
                )
                if picked is None:
                    raise ValueError(f"perk_pick failed at tick={tick_index} choice_index={event.choice_index}")
                continue
            if isinstance(event, UnknownEvent):
                raise ValueError(f"unsupported replay event kind={event.kind!r} at tick={tick_index}")
            raise ValueError(f"unsupported replay event type: {type(event).__name__}")

    def _build_tick_inputs(self, *, tick_index: int) -> list[PlayerInput]:
        replay = self._replay
        if replay is None:
            return []

        packed_tick = replay.inputs[int(tick_index)]
        inputs: list[PlayerInput] = []
        for packed in packed_tick:
            mx, my, ax, ay, flags = packed[:5]
            fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
            inputs.append(
                PlayerInput(
                    move_x=float(mx),
                    move_y=float(my),
                    aim_x=float(ax),
                    aim_y=float(ay),
                    fire_down=fire_down,
                    fire_pressed=fire_pressed,
                    reload_pressed=reload_pressed,
                )
            )
        return inputs

    def _tick_survival(self, *, tick_index: int, dt_frame: float, dt_sim: float) -> None:
        replay = self._replay
        world = self._world
        run = self._survival
        if replay is None or world is None or run is None:
            return

        dt_frame_ms = float(dt_frame) * 1000.0
        run.elapsed_ms += float(dt_frame_ms)

        state = world.state
        state.game_mode = int(GameMode.SURVIVAL)
        state.demo_mode_active = False
        weapon_refresh_available(state)
        perks_rebuild_available(state)

        self._apply_tick_events(tick_index=tick_index, dt_frame=dt_frame)

        player_inputs = self._build_tick_inputs(tick_index=tick_index)
        world.world_state.step(
            float(dt_sim),
            inputs=player_inputs,
            world_size=float(world.world_size),
            damage_scale_by_type=self._damage_scale_by_type,
            detail_preset=5,
            fx_queue=world.fx_queue,
            fx_queue_rotated=world.fx_queue_rotated,
            auto_pick_perks=False,
            game_mode=int(GameMode.SURVIVAL),
            perk_progression_enabled=True,
        )

        stage, milestone_calls = advance_survival_spawn_stage(run.stage, player_level=world.players[0].level if world.players else 1)
        run.stage = stage
        for call in milestone_calls:
            world.creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                state.rng,
                rand=state.rng.rand,
            )

        cooldown, wave_spawns = tick_survival_wave_spawns(
            run.spawn_cooldown_ms,
            dt_frame_ms,
            state.rng,
            player_count=len(world.players),
            survival_elapsed_ms=float(run.elapsed_ms),
            player_experience=int(world.players[0].experience) if world.players else 0,
            terrain_width=int(world.world_size),
            terrain_height=int(world.world_size),
        )
        run.spawn_cooldown_ms = cooldown
        world.creatures.spawn_inits(wave_spawns)

    def _tick_rush(self, *, tick_index: int, dt_frame: float, dt_sim: float) -> None:
        replay = self._replay
        world = self._world
        run = self._rush
        if replay is None or world is None or run is None:
            return

        dt_frame_ms = float(dt_frame) * 1000.0
        run.elapsed_ms += float(dt_frame_ms)

        state = world.state
        state.game_mode = int(GameMode.RUSH)
        state.demo_mode_active = False
        weapon_refresh_available(state)
        perks_rebuild_available(state)

        self._enforce_rush_loadout()

        player_inputs = self._build_tick_inputs(tick_index=tick_index)
        world.world_state.step(
            float(dt_sim),
            inputs=player_inputs,
            world_size=float(world.world_size),
            damage_scale_by_type=self._damage_scale_by_type,
            detail_preset=5,
            fx_queue=world.fx_queue,
            fx_queue_rotated=world.fx_queue_rotated,
            auto_pick_perks=False,
            game_mode=int(GameMode.RUSH),
            perk_progression_enabled=False,
        )

        cooldown, spawns = tick_rush_mode_spawns(
            run.spawn_cooldown_ms,
            dt_frame_ms,
            state.rng,
            player_count=len(world.players),
            survival_elapsed_ms=int(run.elapsed_ms),
            terrain_width=float(world.world_size),
            terrain_height=float(world.world_size),
        )
        run.spawn_cooldown_ms = cooldown
        world.creatures.spawn_inits(spawns)

    def _tick_one(self) -> None:
        replay = self._replay
        world = self._world
        if replay is None or world is None:
            self._finished = True
            return

        tick_index = int(self._tick_index)
        if tick_index >= len(replay.inputs):
            self._finished = True
            return

        dt_frame = float(self._dt_frame)
        dt_sim = time_scale_reflex_boost_bonus(world.state, dt_frame)
        if self._survival is not None:
            self._tick_survival(tick_index=tick_index, dt_frame=dt_frame, dt_sim=dt_sim)
        elif self._rush is not None:
            self._tick_rush(tick_index=tick_index, dt_frame=dt_frame, dt_sim=dt_sim)
        else:  # pragma: no cover
            self._finished = True
            return

        if dt_sim > 0.0:
            world._elapsed_ms += float(dt_sim) * 1000.0
            world._bonus_anim_phase += float(dt_sim) * 1.3
        world.update_camera(float(dt_sim))

        self._tick_index += 1
        if not any(player.health > 0.0 for player in world.players):
            self._finished = True

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return
        if self._finished:
            return

        dt = float(dt)
        if dt < 0.0:
            dt = 0.0
        if dt > 0.1:
            dt = 0.1
        self._dt_accum += dt

        while self._dt_accum + 1e-9 >= self._dt_frame and not self._finished:
            self._tick_one()
            self._dt_accum -= self._dt_frame

        # `GameWorld.open()` schedules terrain generation, but our playback loop
        # steps `WorldState` directly (bypassing `GameWorld.update()`), so we
        # must process pending ground work explicitly.
        world = self._world
        if world is not None and world.ground is not None:
            world.ground.process_pending()

    def draw(self) -> None:
        world = self._world
        if world is not None:
            world.draw(draw_aim_indicators=True)
        else:
            rl.clear_background(rl.BLACK)

        rl.draw_text("REPLAY", 18, 18, 20, rl.Color(255, 255, 255, 220))
        replay = self._replay
        if replay is not None:
            total = len(replay.inputs)
            rl.draw_text(f"{self._tick_index}/{total}", 18, 42, 18, rl.Color(220, 220, 220, 200))
        if self._finished:
            rl.draw_text("REPLAY ENDED (ESC)", 18, 66, 18, rl.Color(220, 220, 220, 200))
