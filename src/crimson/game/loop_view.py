from __future__ import annotations

import webbrowser
from typing import cast

import pyray as rl

from grim.geom import Vec2
from grim.terrain_render import GroundRenderer
from grim.view import View

from ..debug import debug_enabled
from ..demo import DemoView
from ..demo_trial import demo_trial_overlay_info, tick_demo_trial_timers
from ..frontend.boot import BootView
from ..frontend.menu import MenuView, ensure_menu_ground
from ..frontend.panels.alien_zookeeper import AlienZooKeeperView
from ..frontend.panels.base import PanelMenuView
from ..frontend.panels.controls import ControlsMenuView
from ..frontend.panels.credits import CreditsView
from ..frontend.panels.databases import UnlockedPerksDatabaseView, UnlockedWeaponsDatabaseView
from ..frontend.panels.mods import ModsMenuView
from ..frontend.panels.options import OptionsMenuView
from ..frontend.panels.play_game import PlayGameMenuView
from ..frontend.panels.stats import StatisticsMenuView
from ..frontend.pause_menu import PauseMenuView
from ..frontend.transitions import _update_screen_fade
from ..input_codes import input_begin_frame
from ..ui.demo_trial_overlay import DEMO_PURCHASE_URL, DemoTrialOverlayUi
from .high_scores_view import HighScoresView
from .mode_views import QuestGameView, RushGameView, SurvivalGameView, TutorialGameView, TypoShooterGameView
from .quest_views import EndNoteView, QuestFailedView, QuestResultsView, QuestsMenuView
from .types import FrontView, GameState, PauseBackground

class GameLoopView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._boot = BootView(state)
        self._demo = DemoView(state)
        self._menu = MenuView(state)
        self._front_views: dict[str, FrontView] = {
            "open_play_game": PlayGameMenuView(state),
            "open_quests": QuestsMenuView(state),
            "open_pause_menu": PauseMenuView(state),
            "start_quest": QuestGameView(state),
            "quest_results": QuestResultsView(state),
            "quest_failed": QuestFailedView(state),
            "end_note": EndNoteView(state),
            "open_high_scores": HighScoresView(state),
            "start_survival": SurvivalGameView(state),
            "start_rush": RushGameView(state),
            "start_typo": TypoShooterGameView(state),
            "start_tutorial": TutorialGameView(state),
            "open_options": OptionsMenuView(state),
            "open_controls": ControlsMenuView(state),
            "open_statistics": StatisticsMenuView(state),
            "open_weapon_database": UnlockedWeaponsDatabaseView(state),
            "open_perk_database": UnlockedPerksDatabaseView(state),
            "open_credits": CreditsView(state),
            "open_alien_zookeeper": AlienZooKeeperView(state),
            "open_mods": ModsMenuView(state),
            "open_other_games": PanelMenuView(
                state,
                title="Other games",
                body="This menu is out of scope for the rewrite.",
            ),
        }
        self._front_active: FrontView | None = None
        self._front_stack: list[FrontView] = []
        self._active: View = self._boot
        self._demo_trial_overlay = DemoTrialOverlayUi(state.assets_dir)
        self._demo_trial_info = None
        self._demo_active = False
        self._menu_active = False
        self._quit_after_demo = False
        self._screenshot_requested = False
        self._gameplay_views = frozenset(
            {
                self._front_views["start_survival"],
                self._front_views["start_rush"],
                self._front_views["start_typo"],
                self._front_views["start_tutorial"],
                self._front_views["start_quest"],
            }
        )

    def open(self) -> None:
        rl.hide_cursor()
        self._boot.open()

    def should_close(self) -> bool:
        return self._state.quit_requested

    def update(self, dt: float) -> None:
        input_begin_frame()
        console = self._state.console
        console.handle_hotkey()
        console.update(dt)
        _update_screen_fade(self._state, dt)
        if debug_enabled() and (not console.open_flag) and rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True
        if console.open_flag:
            if console.quit_requested:
                self._state.quit_requested = True
                console.quit_requested = False
            return

        self._demo_trial_info = None
        if self._front_active is not None and self._front_active in self._gameplay_views:
            if self._update_demo_trial_overlay(dt):
                return

        self._active.update(dt)
        if self._front_active is not None:
            action = self._front_active.take_action()
            if action == "back_to_menu":
                self._capture_gameplay_ground_for_menu()
                self._state.pause_background = None
                self._front_active.close()
                self._front_active = None
                while self._front_stack:
                    self._front_stack.pop().close()
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
                return
            if action == "back_to_previous":
                if self._front_stack:
                    self._front_active.close()
                    self._front_active = self._front_stack.pop()
                    if self._front_active in self._gameplay_views:
                        self._state.pause_background = None
                    else:
                        reopen_from_child = getattr(self._front_active, "reopen_from_child", None)
                        if callable(reopen_from_child):
                            reopen_from_child()
                    self._active = self._front_active
                    return
                self._front_active.close()
                self._front_active = None
                self._state.pause_background = None
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
                return
            if action == "open_pause_menu":
                pause_view = self._front_views.get("open_pause_menu")
                if pause_view is None:
                    return
                if self._front_active in self._gameplay_views:
                    self._state.pause_background = cast(PauseBackground, self._front_active)
                    self._front_stack.append(self._front_active)
                    pause_view.open()
                    self._front_active = pause_view
                    self._active = pause_view
                    return
                if self._state.pause_background is None:
                    # Options panel uses open_pause_menu as back_action; when no game is
                    # running, treat it like back_to_menu.
                    self._front_active.close()
                    self._front_active = None
                    while self._front_stack:
                        self._front_stack.pop().close()
                    self._menu.open()
                    self._active = self._menu
                    self._menu_active = True
                    return
                self._front_active.close()
                pause_view.open()
                self._front_active = pause_view
                self._active = pause_view
                return
            if action in {"start_survival", "start_rush", "start_typo"}:
                # Temporary: bump the counter on mode start so the Play Game overlay (F1)
                # and Statistics screen reflect activity.
                mode_name = {
                    "start_survival": "survival",
                    "start_rush": "rush",
                    "start_typo": "typo",
                }.get(action)
                if mode_name is not None:
                    self._state.status.increment_mode_play_count(mode_name)
            if action is not None:
                view = self._front_views.get(action)
                if view is not None:
                    if action in {"open_high_scores", "open_weapon_database", "open_perk_database", "open_credits"}:
                        if (self._front_active in self._gameplay_views) and (self._state.pause_background is None):
                            self._state.pause_background = cast(PauseBackground, self._front_active)
                        self._front_stack.append(self._front_active)
                    elif action in {"quest_results", "quest_failed"} and (self._front_active in self._gameplay_views):
                        self._state.pause_background = cast(PauseBackground, self._front_active)
                        self._front_stack.append(self._front_active)
                    else:
                        if action in {
                            "start_survival",
                            "start_rush",
                            "start_typo",
                            "start_tutorial",
                            "start_quest",
                            "open_play_game",
                            "open_quests",
                        }:
                            self._state.pause_background = None
                            while self._front_stack:
                                self._front_stack.pop().close()
                        self._front_active.close()
                    view.open()
                    self._maybe_adopt_menu_ground(action, view)
                    self._front_active = view
                    self._active = view
                    return
        if self._menu_active:
            action = self._menu.take_action()
            if action == "quit_app":
                self._state.quit_requested = True
                return
            if action == "start_demo":
                self._menu.close()
                self._menu_active = False
                self._demo.open()
                self._active = self._demo
                self._demo_active = True
                return
            if action == "quit_after_demo":
                self._menu.close()
                self._menu_active = False
                self._quit_after_demo = True
                self._demo.open()
                self._active = self._demo
                self._demo_active = True
                return
            if action is not None:
                view = self._front_views.get(action)
                if view is not None:
                    self._menu.close()
                    self._menu_active = False
                    view.open()
                    self._maybe_adopt_menu_ground(action, view)
                    self._front_active = view
                    self._active = view
                    return
        if (
            (not self._demo_active)
            and (not self._menu_active)
            and self._front_active is None
            and self._state.demo_enabled
            and self._boot.is_theme_started()
        ):
            self._demo.open()
            self._active = self._demo
            self._demo_active = True
            return
        if self._demo_active and not self._menu_active and self._demo.is_finished():
            self._demo.close()
            self._demo_active = False
            if self._quit_after_demo:
                self._quit_after_demo = False
                self._state.quit_requested = True
                return
            ensure_menu_ground(self._state, regenerate=True)
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
            return
        if (
            (not self._demo_active)
            and (not self._menu_active)
            and self._front_active is None
            and self._boot.is_theme_started()
        ):
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
        if console.quit_requested:
            self._state.quit_requested = True
            console.quit_requested = False

    def _update_demo_trial_overlay(self, dt: float) -> bool:
        if not self._state.demo_enabled:
            return False

        mode_id = int(self._state.config.game_mode)
        quest_major, quest_minor = 0, 0
        if mode_id == 3:
            level = self._state.pending_quest_level or ""
            try:
                major_text, minor_text = level.split(".", 1)
                quest_major = int(major_text)
                quest_minor = int(minor_text)
            except Exception:
                quest_major, quest_minor = 0, 0

        current = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self._state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self._state.demo_trial_elapsed_ms),
            quest_stage_major=int(quest_major),
            quest_stage_minor=int(quest_minor),
        )

        frame_dt = min(float(dt), 0.1)
        dt_ms = int(frame_dt * 1000.0)
        used_ms, grace_ms = tick_demo_trial_timers(
            demo_build=True,
            game_mode_id=int(mode_id),
            overlay_visible=bool(current.visible),
            global_playtime_ms=int(self._state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self._state.demo_trial_elapsed_ms),
            dt_ms=int(dt_ms),
        )
        if used_ms != int(self._state.status.game_sequence_id):
            self._state.status.game_sequence_id = int(used_ms)
        self._state.demo_trial_elapsed_ms = int(grace_ms)

        info = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self._state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self._state.demo_trial_elapsed_ms),
            quest_stage_major=int(quest_major),
            quest_stage_minor=int(quest_minor),
        )
        self._demo_trial_info = info
        if not info.visible:
            return False

        self._demo_trial_overlay.bind_cache(self._state.texture_cache)
        action = self._demo_trial_overlay.update(dt_ms)
        if action == "purchase":
            try:
                webbrowser.open(DEMO_PURCHASE_URL)
            except Exception:
                pass
            return True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or action == "maybe_later":
            self._capture_gameplay_ground_for_menu()
            if self._front_active is not None:
                self._front_active.close()
                self._front_active = None
            while self._front_stack:
                self._front_stack.pop().close()
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
            return True

        return True

    def _maybe_adopt_menu_ground(self, action: str, _view: FrontView) -> None:
        if action not in {"start_survival", "start_rush"}:
            return
        # Native `game_state_set(9)` always calls `gameplay_reset_state()`, which
        # runs `terrain_generate_random()`. Menu terrain should carry back to menu,
        # but entering a fresh gameplay run must regenerate terrain instead of
        # reusing the captured menu render target.

    @staticmethod
    def _steal_ground_from_view(view: FrontView | None) -> GroundRenderer | None:
        if view is None:
            return None
        steal = getattr(view, "steal_ground_for_menu", None)
        if not callable(steal):
            return None
        ground = steal()
        if isinstance(ground, GroundRenderer):
            return ground
        return None

    @staticmethod
    def _menu_ground_camera_from_view(view: FrontView | None) -> Vec2 | None:
        if view is None:
            return None
        camera_getter = getattr(view, "menu_ground_camera", None)
        if not callable(camera_getter):
            return None
        camera = camera_getter()
        if isinstance(camera, Vec2):
            return camera
        return None

    def _replace_menu_ground(self, ground: GroundRenderer, *, camera: Vec2 | None) -> None:
        previous = self._state.menu_ground
        if previous is ground:
            self._state.menu_ground_camera = camera
            return
        if previous is not None and previous.render_target is not None:
            rl.unload_render_texture(previous.render_target)
            previous.render_target = None
        self._state.menu_ground = ground
        self._state.menu_ground_camera = camera

    def _capture_gameplay_ground_for_menu(self) -> None:
        ground: GroundRenderer | None = None
        camera: Vec2 | None = None
        if self._front_active in self._gameplay_views:
            camera = self._menu_ground_camera_from_view(self._front_active)
            ground = self._steal_ground_from_view(self._front_active)
        if ground is None:
            for view in reversed(self._front_stack):
                if view in self._gameplay_views:
                    camera = self._menu_ground_camera_from_view(view)
                    ground = self._steal_ground_from_view(view)
                    if ground is not None:
                        break
        if ground is None:
            return
        self._replace_menu_ground(ground, camera=camera)

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def draw(self) -> None:
        self._active.draw()
        info = self._demo_trial_info
        if info is not None and getattr(info, "visible", False):
            self._demo_trial_overlay.bind_cache(self._state.texture_cache)
            self._demo_trial_overlay.draw(info)
        self._state.console.draw()

    def close(self) -> None:
        if self._menu_active:
            self._menu.close()
        if self._front_active is not None:
            self._front_active.close()
        while self._front_stack:
            self._front_stack.pop().close()
        if self._demo_active:
            self._demo.close()
        self._demo_trial_overlay.close()
        if self._state.menu_ground is not None and self._state.menu_ground.render_target is not None:
            rl.unload_render_texture(self._state.menu_ground.render_target)
            self._state.menu_ground.render_target = None
        self._boot.close()
        self._state.console.close()
        rl.show_cursor()

