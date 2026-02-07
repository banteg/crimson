from __future__ import annotations

from pathlib import Path

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.geom import Vec2
from grim.view import ViewContext

from ..game_modes import GameMode
from ..game_world import GameWorld
from ..gameplay import (
    PlayerInput,
    perk_selection_current_choices,
    perk_selection_pick,
    weapon_assign_player,
)
from ..replay import (
    PerkMenuOpenEvent,
    PerkPickEvent,
    Replay,
    UnknownEvent,
    load_replay_file,
    unpack_packed_player_input,
    unpack_input_flags,
    warn_on_game_version_mismatch,
)
from ..sim.runners.common import build_damage_scale_by_type, status_from_snapshot
from ..sim.sessions import RushDeterministicSession, SurvivalDeterministicSession
from ..weapons import WeaponId

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE
_PLAYBACK_SPEED_STEPS: tuple[float, ...] = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0)
_DEFAULT_SPEED_INDEX = 2
_SKIP_SHORT_SECONDS = 5.0
_SKIP_LONG_SECONDS = 30.0


class ReplayPlaybackMode:
    def __init__(self, ctx: ViewContext, *, replay_path: Path) -> None:
        self._ctx = ctx
        self._replay_path = Path(replay_path)

        self.close_requested = False

        self._replay: Replay | None = None
        self._world: GameWorld | None = None
        self._events_by_tick: dict[int, list[object]] = {}
        self._damage_scale_by_type = build_damage_scale_by_type()
        self._small: SmallFontData | None = None
        self._missing_assets: list[str] = []

        self._tick_rate = 60
        self._dt_frame = 1.0 / 60.0
        self._dt_accum = 0.0
        self._tick_index = 0
        self._finished = False
        self._terminal_events_applied = False
        self._paused = False
        self._speed_index = _DEFAULT_SPEED_INDEX

        self._survival: SurvivalDeterministicSession | None = None
        self._rush: RushDeterministicSession | None = None

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._ctx.assets_dir, self._missing_assets)
        except Exception:
            self._small = None

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
        self._terminal_events_applied = False
        self._paused = False
        self._speed_index = _DEFAULT_SPEED_INDEX

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
            weapon_usage_counts=replay.header.status.weapon_usage_counts,
        )
        # Important: `GameWorld.open()` consumes RNG for terrain generation. Treat `replay.header.seed` as the
        # gameplay RNG state at tick 0 and set it after `open()` to keep headless verification deterministic.
        world.state.rng.srand(int(replay.header.seed))

        self._world = world

        if int(replay.header.game_mode_id) == int(GameMode.SURVIVAL):
            self._survival = SurvivalDeterministicSession(
                world=world.world_state,
                world_size=float(world.world_size),
                damage_scale_by_type=self._damage_scale_by_type,
                fx_queue=world.fx_queue,
                fx_queue_rotated=world.fx_queue_rotated,
                detail_preset=5,
                fx_toggle=0,
                game_tune_started=bool(world._game_tune_started),
                clear_fx_queues_each_tick=False,
            )
            self._rush = None
        elif int(replay.header.game_mode_id) == int(GameMode.RUSH):
            if replay.events:
                raise ValueError("rush replay does not support events")
            self._survival = None
            self._rush = RushDeterministicSession(
                world=world.world_state,
                world_size=float(world.world_size),
                damage_scale_by_type=self._damage_scale_by_type,
                fx_queue=world.fx_queue,
                fx_queue_rotated=world.fx_queue_rotated,
                detail_preset=5,
                fx_toggle=0,
                game_tune_started=bool(world._game_tune_started),
                clear_fx_queues_each_tick=False,
                enforce_loadout=self._enforce_rush_loadout,
            )
            self._enforce_rush_loadout()
        else:
            raise ValueError(f"unsupported replay game_mode_id: {int(replay.header.game_mode_id)}")

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        world = self._world
        self._world = None
        if world is not None:
            world.close()

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color, *, scale: float = 1.0) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, pos, scale, color)
        else:
            rl.draw_text(text, int(pos.x), int(pos.y), int(20 * scale), color)

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
            if isinstance(event, PerkMenuOpenEvent):
                perk_selection_current_choices(
                    world.state,
                    world.players,
                    world.state.perk_selection,
                    game_mode=int(replay.header.game_mode_id),
                    player_count=len(world.players),
                )
                continue
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
            mx, my, ax, ay, flags = unpack_packed_player_input(packed)
            fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
            inputs.append(
                PlayerInput(
                    move=Vec2(float(mx), float(my)),
                    aim=Vec2(float(ax), float(ay)),
                    fire_down=fire_down,
                    fire_pressed=fire_pressed,
                    reload_pressed=reload_pressed,
                )
            )
        return inputs

    def _tick_survival(self, *, tick_index: int, dt_frame: float) -> float:
        replay = self._replay
        world = self._world
        session = self._survival
        if replay is None or world is None or session is None:
            return 0.0

        self._apply_tick_events(tick_index=tick_index, dt_frame=dt_frame)

        player_inputs = self._build_tick_inputs(tick_index=tick_index)
        tick = session.step_tick(
            dt_frame=float(dt_frame),
            inputs=player_inputs,
        )
        world.apply_step_result(
            tick.step,
            game_tune_started=bool(session.game_tune_started),
            apply_audio=True,
            update_camera=False,
        )

        return float(tick.step.dt_sim)

    def _tick_rush(self, *, tick_index: int, dt_frame: float) -> float:
        replay = self._replay
        world = self._world
        session = self._rush
        if replay is None or world is None or session is None:
            return 0.0

        player_inputs = self._build_tick_inputs(tick_index=tick_index)
        tick = session.step_tick(
            dt_frame=float(dt_frame),
            inputs=player_inputs,
        )
        world.apply_step_result(
            tick.step,
            game_tune_started=bool(session.game_tune_started),
            apply_audio=True,
            update_camera=False,
        )
        return float(tick.step.dt_sim)

    def _tick_one(self) -> None:
        replay = self._replay
        world = self._world
        if replay is None or world is None:
            self._finished = True
            return

        tick_index = int(self._tick_index)
        if tick_index >= len(replay.inputs):
            if (not self._terminal_events_applied) and tick_index == len(replay.inputs):
                self._apply_tick_events(tick_index=tick_index, dt_frame=float(self._dt_frame))
                self._terminal_events_applied = True
            self._finished = True
            return

        dt_frame = float(self._dt_frame)
        if self._survival is not None:
            dt_sim = self._tick_survival(tick_index=tick_index, dt_frame=dt_frame)
        elif self._rush is not None:
            dt_sim = self._tick_rush(tick_index=tick_index, dt_frame=dt_frame)
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

    def _playback_speed(self) -> float:
        return float(_PLAYBACK_SPEED_STEPS[int(self._speed_index)])

    def _change_speed(self, delta: int) -> None:
        idx = int(self._speed_index) + int(delta)
        idx = max(0, min(idx, len(_PLAYBACK_SPEED_STEPS) - 1))
        self._speed_index = idx

    def _skip_forward_seconds(self, seconds: float) -> None:
        replay = self._replay
        if replay is None or self._finished:
            return
        ticks = int(round(float(seconds) * float(self._tick_rate)))
        if ticks <= 0:
            return
        target = min(len(replay.inputs), int(self._tick_index) + int(ticks))
        while self._tick_index < target and not self._finished:
            self._tick_one()
        # Avoid accidental overshoot from stale accumulated frame time after seek.
        self._dt_accum = 0.0

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._paused = not bool(self._paused)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._change_speed(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._change_speed(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._speed_index = _DEFAULT_SPEED_INDEX
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._skip_forward_seconds(_SKIP_SHORT_SECONDS)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._skip_forward_seconds(_SKIP_LONG_SECONDS)

        if not self._finished and (not self._paused):
            dt = float(dt)
            if dt < 0.0:
                dt = 0.0
            if dt > 0.1:
                dt = 0.1
            self._dt_accum += dt * self._playback_speed()

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

        self._draw_ui_text("REPLAY", Vec2(18.0, 18.0), rl.Color(255, 255, 255, 220), scale=1.0)
        replay = self._replay
        if replay is not None:
            total = len(replay.inputs)
            elapsed_s = float(self._tick_index) / float(self._tick_rate)
            total_s = float(total) / float(self._tick_rate)
            self._draw_ui_text(
                f"{self._tick_index}/{total}  {elapsed_s:.1f}s/{total_s:.1f}s",
                Vec2(18.0, 42.0),
                rl.Color(220, 220, 220, 200),
                scale=0.9,
            )
        status = "PAUSED" if self._paused else "PLAYING"
        self._draw_ui_text(f"{status}  {self._playback_speed():.2f}x", Vec2(18.0, 66.0), rl.Color(220, 220, 220, 200), scale=0.9)
        self._draw_ui_text(
            "[/] speed  1 reset  SPACE pause  RIGHT +5s  PGDN +30s",
            Vec2(18.0, 90.0),
            rl.Color(190, 190, 190, 200),
            scale=0.9,
        )
        if self._finished:
            self._draw_ui_text("REPLAY ENDED (ESC)", Vec2(18.0, 114.0), rl.Color(220, 220, 220, 200), scale=0.9)
