"""Watching a replay (docs/rewrite/replay-viewer.md): a scrub bar that seeks anywhere, backwards too, a box for each
perk pick, and the original's game over screen at the end.

The replay plays at once while a preparing pass (`ReplayPreparation`) plays the whole recording in a process of its
own, keeping a keyframe every half second and logging every bake into the terrain. A seek restores the last
keyframe before its tick, rebuilds the terrain to it (`TerrainHistory`) and plays on, undrawn and unheard, to the
tick; one forward that no keyframe beats just plays on. It reaches as far as the pass has. While the replay plays,
the viewer keeps to dim bands of its own that stay clear of the game's HUD; the end is the original's.
"""

from __future__ import annotations

import bisect
import datetime as dt
import time

import msgspec

from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.audio import AudioState, update_audio
from grim.color import grim_color
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.music import play_music, resume_music, stop_music
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.view import ViewContext

from ..game_states import GameStateId
from ..modes.replay_playback_mode import ReplayPlaybackMode
from ..perks.ids import perk_display_name
from ..persistence.highscores import HighScoreRecord
from ..replay.driver.prepare import Mark, MarkKind, Pick, ReplayPreparation
from ..replay.types import Replay
from ..sim.run_result import RunOutcome
from ..ui.animation import ui_elements_max_timeline
from ..ui.button import UiButtonState, button_draw, button_update
from ..ui.cursor import ui_cursor_render
from ..ui.focus import UiFocus
from ..ui.highscore_card import ui_text_input_render
from ..ui.menu_panel import draw_ui_panel, ui_panel_rect
from ..world.terrain_history import TerrainHistory
from .actions import Route, ScreenAction
from .results.game_over import GAME_OVER_BANNER_X_OFFSET, TEXTURE_TOP_BANNER_H, TEXTURE_TOP_BANNER_W

SPEEDS = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0)
NORMAL_SPEED = 2
# How long a pick's box shows, in the viewer's seconds.
PICK_SECONDS = 3.0
# A frame's share of ticks: past it, playback runs slower than asked, as fast as the simulation plays.
FRAME_TICK_SECONDS = 1.0 / 30.0

# Survival's milestone waves (`survival_update`), by the spawn stage they start.
WAVES = (
    "",
    "Alien rings",
    "Red alien boss",
    "Spider swarm",
    "Fast aliens",
    "Stop-and-go spiders",
    "Spider boss",
    "Splitter spider",
    "Splitter spiders",
    "Plasma spiders",
    "Second spider boss",
)

# The bar's band: the segments' row, with room above for the marks.
BAR_H = 48.0
IDLE_SECONDS = 2.5
PIP_W, PIP_H = 8.0, 16.0
SCRUB_X = 112.0
# The pick box, right-aligned under where the level-up prompt swings in.
CARD_Y = 88.0
# The end screen's card and buttons under its banner: the original's layout, the card the taller for the runner's
# name and date it shows outside the game over screen.
OVER_CARD_Y = 80.0
OVER_BUTTONS_Y = 250.0


class WatchCard(msgspec.Struct):
    """The run's score card, as the high score screen draws it, and its rank there (0: none)."""

    record: HighScoreRecord
    rank: int = 0


def replay_card(replay: Replay, *, name: str, day: dt.date) -> WatchCard:
    """A card from the replay's own result, for a replay that comes without a high score row."""
    result = replay.result
    record = HighScoreRecord.blank(rand_value=0)
    record.set_name(name)
    record.game_mode_id = replay.run.game_mode_id
    record.quest_level = replay.run.quest_level
    record.run_elapsed_ms = result.quest_final_ms if result.quest_final_ms is not None else result.elapsed_ms
    if result.players:
        record.score_xp = result.players[0].experience
        record.most_used_weapon_id = result.players[0].most_used_weapon_id
    record.shots_fired = result.shots_fired
    record.shots_hit = result.shots_hit
    record.creature_kill_count = result.kills
    record.ensure_date_fields(day)
    return WatchCard(record)


def _clock(tick: int) -> str:
    seconds = tick // 60
    return f"{seconds // 60}:{seconds % 60:02d}"


def _ease(t: float) -> float:
    return 1.0 - (1.0 - t) * (1.0 - t)


class ReplayViewer:
    """Plays a replay with the viewer over it: in the game, a screen above the high scores; standalone, the window."""

    def __init__(
        self,
        ctx: ViewContext,
        *,
        replay: Replay,
        config: CrimsonConfig,
        console: ConsoleState,
        card: WatchCard,
        audio: AudioState | None = None,
        leave_label: str = "High scores",
        background: bool = True,
    ) -> None:
        self._replay = replay
        self._config = config
        self._audio = audio
        self._card = card
        self._background = background
        self.player = ReplayPlaybackMode(
            ctx, replay=replay, config=config, console=console, audio=audio, plays_music=False,
        )
        self.preparation: ReplayPreparation | None = None
        self._history: TerrainHistory | None = None
        self._focus = UiFocus()
        self._again = UiButtonState("Watch Again", force_wide=True)
        self._leave = UiButtonState(leave_label, force_wide=True)
        self.close_requested = False
        self.speed = NORMAL_SPEED
        self.paused = False
        self._step = False
        self._banked = 0.0
        # A tick the viewer asked for (from 1), or 0.
        self._seek = 0
        self._next_pick = 0
        self.card_pick = -1  # the pick the box shows
        self._card_left = 0.0
        self._card_in = 0.0  # the box's slide in: 0 off, 1 in
        self._card_box = (0.0, 0.0, 0.0, 0.0)
        self._end_in = 0.0
        self._shown = 1.0  # the bar's slide: 0 away, 1 up
        self._idle = 0.0
        self._last_mouse = Vec2()
        self._dragging = False
        self._clicked = False
        self._dt = 0.0

    # -- the screen ------------------------------------------------------------------------------------------------

    def open(self) -> None:
        self.player.open()
        runtime = self.player.runtime
        self._history = TerrainHistory(runtime.render_resources, self.player.driver.terrain_setup)
        self._history.open()
        self.preparation = ReplayPreparation(self._replay, background=self._background)
        self._tune()

    def close(self) -> None:
        if self.preparation is not None:
            self.preparation.close()
            self.preparation = None
        if self._history is not None:
            self._history.close()
            self._history = None
        self.player.close()

    def take_action(self) -> ScreenAction | None:
        if not self.close_requested:
            return None
        self.close_requested = False
        return Route.BACK

    def should_close(self) -> bool:
        return bool(self.close_requested)

    def consume_screenshot_request(self) -> bool:
        return False

    # -- where playback is ---------------------------------------------------------------------------------------

    @property
    def tick(self) -> int:
        return self.player.tick_index

    @property
    def ticks(self) -> int:
        """The run's ticks: the recording's, up to a tick the simulation refuses."""
        prep = self.preparation
        ticks = self.player.ticks
        if prep is not None and prep.ended:
            ticks = min(ticks, prep.tick)
        return ticks

    @property
    def reach(self) -> int:
        """The furthest tick a seek goes to: as far as the pass, or playback, has played."""
        prep = self.preparation
        return max(self.tick, 0 if prep is None else prep.tick)

    @property
    def ended(self) -> bool:
        return self.tick >= self.ticks

    def ask(self, tick: int) -> None:
        """A tick to go to, from the first."""
        self._seek = max(1, tick)

    def seek(self, target: int) -> None:
        """Playback goes to `target` ticks in: on from where it is when no keyframe is nearer, else from the last
        keyframe before it, with the terrain rebuilt to it. The ticks it plays are not drawn or heard."""
        prep = self.preparation
        assert prep is not None
        target = max(1, min(target, self.ticks, self.reach))
        key = prep.key_before(target)
        if key is not None and (self.tick >= target or self.tick < key.tick):
            self.player.restore(key)
            assert self._history is not None
            self._history.rebuild(prep, key.bakes)
        if self.tick < target:
            self.player.run(target - self.tick, quiet=True)
        self.player.settle_hud()
        self._next_pick = bisect.bisect_right(prep.picks, self.tick, key=lambda pick: pick.tick)
        self.card_pick = -1
        self._card_in = 0.0
        self._tune()

    def _tune(self) -> None:
        """The tune the run has where playback is: the one it last started, or before the first, an in-game tune
        already playing (a scrub back keeps it) and none other."""
        audio = self._audio
        prep = self.preparation
        if audio is None or prep is None:
            return
        music = audio.music
        index = bisect.bisect_right(prep.tunes, self.tick, key=lambda tune: tune.tick) - 1
        want = None
        fade_in = False
        if index >= 0:
            tune = prep.tunes[index]
            fade_in = tune.fade_in
            want = tune.track or (music.queue[tune.draw % len(music.queue)] if music.queue else None)
        playing = music.active_track
        if want == playing:
            return
        if want is None:
            if playing is not None and playing not in music.queue:
                stop_music(music)
            return
        if fade_in:
            play_music(music, want, fade_in=True)
        else:
            resume_music(music, want)

    # -- a frame -------------------------------------------------------------------------------------------------

    def update(self, dt: float) -> None:
        dt = min(max(0.0, float(dt)), 0.1)
        self._dt = dt
        self.player.set_frame_dt(dt)
        self._focus.begin_frame(int(dt * 1000.0))
        prep = self.preparation
        assert prep is not None and self._history is not None
        prep.poll()
        self._history.feed(prep)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return
        self._keys()
        self._pointer(dt)
        from_tick = self.tick
        ran = 0
        if self._seek:
            self.seek(self._seek)
            self._seek = 0
        elif not self.ended and (not self.paused or self._step):
            ran = self._play(dt)
            self._show_picks(from_tick)
        self._step = False
        self._update_card(dt)
        self._update_end(dt)
        self._tune()
        if self._audio is not None:
            update_audio(self._audio, dt, advance_sfx=ran == 0)

    def _play(self, dt: float) -> int:
        """The frame's ticks at the viewer's speed (a paused step: one), as many as a frame's share affords."""
        if self.paused:
            return self.player.run(1)
        self._banked += dt * SPEEDS[self.speed]
        due = int(self._banked * 60.0 + 1e-4)
        self._banked -= due / 60.0
        ran = 0
        start = time.perf_counter()
        while ran < due and not self.ended:
            ran += self.player.run(min(8, due - ran))
            if time.perf_counter() - start > FRAME_TICK_SECONDS:
                self._banked = 0.0
                break
        return ran

    def _show_picks(self, from_tick: int) -> None:
        """The box shows the last pick playback passed."""
        prep = self.preparation
        assert prep is not None
        while self._next_pick < len(prep.picks) and prep.picks[self._next_pick].tick <= self.tick:
            if prep.picks[self._next_pick].tick > from_tick:
                self.card_pick = self._next_pick
                self._card_left = PICK_SECONDS
            self._next_pick += 1

    def _keys(self) -> None:
        pressed = rl.is_key_pressed
        keys = rl.KeyboardKey
        second = 60
        if pressed(keys.KEY_SPACE):
            # Pause, or from the end, play again.
            if self.ended:
                self.ask(1)
                self.paused = False
            else:
                self.paused = not self.paused
        if pressed(keys.KEY_PERIOD) and self.paused:
            self._step = True
        if pressed(keys.KEY_COMMA) and self.paused:
            self.ask(self.tick - 1)
        if pressed(keys.KEY_LEFT_BRACKET):
            self.speed = max(self.speed - 1, 0)
        if pressed(keys.KEY_RIGHT_BRACKET):
            self.speed = min(self.speed + 1, len(SPEEDS) - 1)
        if pressed(keys.KEY_ONE):
            self.speed = NORMAL_SPEED
        for key, seconds in (
            (keys.KEY_LEFT, -5),
            (keys.KEY_RIGHT, 5),
            (keys.KEY_PAGE_UP, -30),
            (keys.KEY_PAGE_DOWN, 30),
        ):
            if pressed(key):
                self.ask(self.tick + seconds * second)
        if pressed(keys.KEY_HOME):
            self.ask(1)
        if pressed(keys.KEY_END):
            self.ask(self.ticks)

    # -- the scrub bar ---------------------------------------------------------------------------------------------

    def _bar_y(self) -> float:
        return float(canvas.height()) - BAR_H * self._shown

    def _pips(self) -> int:
        return int((float(canvas.width()) - SCRUB_X - 120.0) / PIP_W)

    def _scrub_y(self) -> float:
        return self._bar_y() + 18.0

    def _tick_at(self, x: float) -> int:
        t = (x - SCRUB_X) / (self._pips() * PIP_W)
        return round(min(max(t, 0.0), 1.0) * self.ticks)

    def _x_of(self, tick: int) -> float:
        ticks = self.ticks
        return SCRUB_X + (tick / ticks if ticks else 0.0) * self._pips() * PIP_W

    def _over_scrub(self, pos: Vec2) -> bool:
        y = self._scrub_y()
        return SCRUB_X - 4 <= pos.x <= SCRUB_X + self._pips() * PIP_W + 4 and y - 10 <= pos.y <= y + PIP_H + 6

    def _over_card(self, pos: Vec2) -> bool:
        x, y, w, h = self._card_box
        return self._card_in > 0 and x <= pos.x < x + w and y <= pos.y < y + h

    def _pointer(self, dt: float) -> None:
        """The cursor and the scrub bar: a drag seeks as it goes, and a click on the world pauses or plays on."""
        mouse = Vec2.from_xy(canvas.mouse_position())
        down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._clicked = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if mouse != self._last_mouse or down:
            self._idle = 0.0
        else:
            self._idle += dt
        self._last_mouse = mouse
        height = float(canvas.height())
        want = (
            self.paused or self.ended or self._idle < IDLE_SECONDS or self._dragging or mouse.y > height - BAR_H - 16
        )
        self._shown = min(1.0, max(0.0, self._shown + (dt if want else -dt) * 6.0))
        on_bar = self._shown > 0.5 and mouse.y >= self._bar_y()
        if self._clicked and self._shown > 0.5 and self._over_scrub(mouse):
            self._dragging = True
        elif self._clicked and not on_bar and not self._over_card(mouse) and not self.ended:
            self.paused = not self.paused
        if not down:
            self._dragging = False
        if self._dragging and (at := self._tick_at(mouse.x)) != self.tick:
            self.ask(at)
        if self._clicked and self._shown > 0.0 and self._speed_rect().contains(mouse):
            self.speed = (self.speed + 1) % len(SPEEDS)

    def _speed_text(self) -> str:
        return "Paused" if self.paused else f"{SPEEDS[self.speed]:g}x"

    def _speed_rect(self) -> Rect:
        """Paused, or the speed, left of the bar; a click on it steps the speed up, round to the slowest."""
        font = self.player.runtime.render_resources.resources.small_font
        left = SCRUB_X - 12.0 - measure_small_text_width(font, self._speed_text())
        return Rect.from_top_left(Vec2(left - 4.0, self._scrub_y() - 2.0), SCRUB_X - left, 20.0)

    def _text(self, resources: RuntimeResources, text: str, pos: Vec2, color: rl.Color, *, shadow: bool = False) -> None:
        font = resources.small_font
        if shadow:
            draw_small_text(font, text, pos + Vec2(1.0, 1.0), grim_color(0.0, 0.0, 0.0, color.a / 255.0 * 0.8))
        draw_small_text(font, text, pos, color)

    def _rect(self, x: float, y: float, w: float, h: float, color: rl.Color) -> None:
        rl.draw_rectangle_rec(rl_rectangle(x, y, w, h), color)

    def _pip(self, texture: rl.Texture, x: float, y: float, alpha: float) -> None:
        rl.draw_texture_pro(
            texture,
            rl_rectangle(0.0, 0.0, float(texture.width), float(texture.height)),
            rl_rectangle(x, y, PIP_W, PIP_H),
            rl_vector2(0.0, 0.0),
            0.0,
            grim_color(1.0, 1.0, 1.0, alpha),
        )

    def _mark_label(self, mark: Mark) -> str:
        match mark.kind:
            case MarkKind.WAVE:
                return f"Wave {mark.value}: {WAVES[mark.value] if mark.value < len(WAVES) else ''}"
            case MarkKind.ENERGIZER:
                return "Energizer"
            case MarkKind.PICK:
                assert self.preparation is not None
                pick = self.preparation.picks[mark.value]
                return f"Level {pick.level}: {self._perk_name(pick, pick.pick.chosen)}"

    def _perk_name(self, pick: Pick, index: int) -> str:
        return perk_display_name(pick.pick.offered[index], violence_disabled=int(self._replay.run.violence_disabled))

    def _draw_bar(self, resources: RuntimeResources) -> None:
        prep = self.preparation
        assert prep is not None
        width = float(canvas.width())
        # A dim band along the bottom keeps the segments clear of any ground, snow too, and leaves the game's own
        # HUD its look.
        self._rect(0.0, self._bar_y(), width, BAR_H, grim_color(0.0, 0.0, 0.0, 0.45))
        pips = self._pips()
        ticks = self.ticks
        lit = pips * self.tick // ticks if ticks else pips
        # The segments the pass has not reached yet are fainter: a seek goes no further.
        reached = pips * self.reach // ticks if ticks else pips
        y = self._scrub_y()
        rect_on = resources.texture(TextureId.UI_RECT_ON)
        rect_off = resources.texture(TextureId.UI_RECT_OFF)
        for i in range(pips):
            x = SCRUB_X + i * PIP_W
            if i < lit:
                self._pip(rect_on, x, y, 1.0)
            else:
                self._pip(rect_off, x, y, 0.5 if i < reached else 0.2)
        for mark in prep.marks:
            color, height = grim_color(1.0, 1.0, 1.0, 0.8), 5.0
            if mark.kind == MarkKind.WAVE:
                color, height = grim_color(1.0, 0.35, 0.25, 1.0), 8.0
            elif mark.kind == MarkKind.ENERGIZER:
                color, height = grim_color(0.3, 0.85, 1.0, 1.0), 8.0
            self._rect(float(int(self._x_of(mark.tick))), y - height - 2.0, 2.0, height, color)
        # The playhead.
        self._rect(float(int(self._x_of(self.tick))) - 1.0, y - 3.0, 3.0, PIP_H + 6.0, grim_color(1.0, 1.0, 1.0, 1.0))

        mouse = Vec2.from_xy(canvas.mouse_position())
        speed_rect = self._speed_rect()
        tint = grim_color(1.0, 1.0, 1.0, 0.9) if speed_rect.contains(mouse) else grim_color(0.75, 0.78, 0.82, 0.9)
        self._text(resources, self._speed_text(), Vec2(speed_rect.left + 4.0, y + 1.0), tint, shadow=True)
        line = f"{_clock(self.tick)} / {_clock(ticks)}"
        self._text(resources, line, Vec2(SCRUB_X + pips * PIP_W + 12.0, y + 1.0), grim_color(0.9, 0.9, 0.9, 0.9), shadow=True)

        # Under the cursor: the time, and a mark near it.
        if self._over_scrub(mouse) or self._dragging:
            tip = _clock(self._tick_at(mouse.x))
            near = next((mark for mark in prep.marks if abs(self._x_of(mark.tick) - mouse.x) <= 4.0), None)
            if near is not None:
                tip += f"  {self._mark_label(near)}"
            tip_w = measure_small_text_width(resources.small_font, tip) + 12.0
            x = min(max(mouse.x - tip_w * 0.5, 4.0), width - tip_w - 4.0)
            self._rect(x, y - 32.0, tip_w, 18.0, grim_color(0.0, 0.0, 0.0, 0.8))
            self._text(resources, tip, Vec2(x + 6.0, y - 30.0), grim_color(1.0, 1.0, 1.0, 1.0))

    # -- the pick box ----------------------------------------------------------------------------------------------

    def _update_card(self, dt: float) -> None:
        if not self.paused and self.card_pick >= 0:
            self._card_left -= dt
        showing = self.card_pick >= 0 and self._card_left > 0.0
        self._card_in = min(1.0, max(0.0, self._card_in + (dt if showing else -dt) * 5.0))
        if self._card_in <= 0.0 and not showing:
            self.card_pick = -1

    def _draw_card(self, resources: RuntimeResources) -> None:
        """The last pick's box under the level-up prompt: the menu's offers, the chosen one lit."""
        prep = self.preparation
        assert prep is not None
        if self.card_pick < 0 or self._card_in <= 0.0:
            return
        pick = prep.picks[self.card_pick]
        font = resources.small_font
        names = [self._perk_name(pick, i) for i in range(len(pick.pick.offered))]
        w = max(measure_small_text_width(font, name) for name in names) + 28.0
        x = float(canvas.width()) - (w + 8.0) * _ease(self._card_in)
        y = CARD_Y
        h = 32.0 + len(names) * 15.0
        self._card_box = (x, y, w, h)
        # The offers in a dim box with the perk menu's blue along its top.
        self._rect(x, y, w, h, grim_color(0.0, 0.0, 0.0, 0.55))
        self._rect(x, y, w, 2.0, grim_color(0.27, 0.51, 0.86, 0.9))
        self._text(resources, f"Level {pick.level}", Vec2(x + 12.0, y + 8.0), grim_color(0.5, 0.75, 1.0, 1.0))
        for i, name in enumerate(names):
            lit = i == pick.pick.chosen
            color = grim_color(1.0, 1.0, 1.0, 1.0) if lit else grim_color(0.62, 0.64, 0.68, 0.75)
            self._text(resources, name, Vec2(x + 12.0, y + 26.0 + i * 15.0), color)

    # -- the end ---------------------------------------------------------------------------------------------------

    def _end_panel(self) -> Rect:
        """The game over screen's panel, sliding in from the left; its banner's corner is where the screen lays out
        from (`game_over_screen_update`)."""
        panel = ui_panel_rect(30, float(ui_elements_max_timeline(GameStateId.GAME_OVER)), float(canvas.width()))
        return panel.offset(dx=-(1.0 - _ease(self._end_in)) * 560.0)

    def _end_corner(self) -> Vec2:
        return self._end_panel().top_left + Vec2(GAME_OVER_BANNER_X_OFFSET, 40.0)

    def _update_end(self, dt: float) -> None:
        if not self.ended:
            self._end_in = 0.0
            return
        self._end_in = min(1.0, self._end_in + dt * 2.5)
        resources = self.player.runtime.render_resources.resources
        mouse = canvas.mouse_position()
        at = self._end_corner() + Vec2(52.0, OVER_BUTTONS_Y)
        dt_ms = dt * 1000.0
        click = self._clicked
        if button_update(resources, self._again, focus=self._focus, pos=at, dt_ms=dt_ms, mouse=mouse, click=click):
            self.ask(1)
            self.paused = False
        at = at.offset(dy=32.0)
        if button_update(resources, self._leave, focus=self._focus, pos=at, dt_ms=dt_ms, mouse=mouse, click=click):
            self.close_requested = True

    def _draw_end(self, resources: RuntimeResources) -> None:
        """The run's end as the original ends one: the game over screen's panel and banner, whether it played as
        recorded where the original says a score is too low, the run's card and its buttons."""
        draw_ui_panel(resources, 30, self._end_panel(), shadow=self._config.display.shadows_enabled)
        corner = self._end_corner()
        outcome = self._replay.result.outcome
        if outcome in (RunOutcome.DEATH, RunOutcome.QUEST_COMPLETED):
            banner = resources.texture(TextureId.UI_TEXT_REAPER if outcome == RunOutcome.DEATH else TextureId.UI_TEXT_WELL_DONE)
            rl.draw_texture_pro(
                banner,
                rl_rectangle(0.0, 0.0, float(banner.width), float(banner.height)),
                rl_rectangle(corner.x - 2.0, corner.y, TEXTURE_TOP_BANNER_W, TEXTURE_TOP_BANNER_H),
                rl_vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )
        else:
            # A run left before its end has no banner of the original's: it says so.
            self._text(resources, "The run was left here.", corner + Vec2(38.0, 30.0), grim_color(1.0, 1.0, 1.0, 1.0))
        player = self.player
        if player.stopped_reason is not None:
            verdict, color = player.stopped_reason, grim_color(1.0, 0.5, 0.5, 0.9)
        elif player.played_as_recorded:
            verdict, color = "Played as recorded.", grim_color(0.7, 1.0, 0.7, 0.9)
        else:
            verdict, color = "This run played differently.", grim_color(1.0, 0.5, 0.5, 0.9)
        self._text(resources, verdict, corner + Vec2(38.0, 62.0), color)
        ui_text_input_render(
            corner + Vec2(30.0, OVER_CARD_Y), self._card.record, 1.0, self._card.rank,
            game_state=GameStateId.HIGHSCORES, ui_phase=0, resources=resources,
            mouse=canvas.mouse_position(), dt=self._dt,
        )
        at = corner + Vec2(52.0, OVER_BUTTONS_Y)
        button_draw(resources, self._again, focus=self._focus, pos=at)
        button_draw(resources, self._leave, focus=self._focus, pos=at.offset(dy=32.0))

    def draw(self) -> None:
        self.player.draw()
        resources = self.player.runtime.render_resources.resources
        self._draw_card(resources)
        if self.ended:
            self._draw_end(resources)
        if self._shown > 0.0:
            self._draw_bar(resources)
        if self._shown > 0.0 or self.ended:
            ui_cursor_render(resources, dt=self._dt)
