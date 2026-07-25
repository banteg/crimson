from __future__ import annotations

import math
import webbrowser

from grim.assets import TextureId
from grim.audio import update_audio
from grim.fonts.grim_mono import GrimMonoFont, draw_grim_mono_text, load_grim_mono_font
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl

from .creatures.spawn import RANDOM_HEADING_SENTINEL, SpawnId
from .game.types import GameState
from .game_modes import GameMode
from .quests import quest_by_level
from .quests.level import QuestLevel
from .rng_caller_static import RngCallerStatic
from .screens.assets import require_runtime_resources
from .sim.bootstrap import advance_explicit_terrain
from .sim.input import PlayerInput
from .sim.input_providers import FrameContext, LocalInputRuntime
from .sim.state_types import PlayerState
from .terrain_slots import Q2_TERRAIN_SLOTS, TerrainSlotTriplet
from .ui.cursor import draw_menu_cursor
from .ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from .weapon_runtime import weapon_assign_player
from .weapons import WeaponId, weapon_display_name
from .world import WorldRuntime
from .world.standalone_tick_harness import StandaloneTickHarness

WORLD_SIZE = 1024.0
DEMO_VARIANT_COUNT = 6

_DEMO_UPSELL_MESSAGES: tuple[str, ...] = (
    "Want more Levels?",
    "Want more Weapons?",
    "Want more Perks?",
    "Want unlimited Play time?",
    "Want to post your high scores?",
)

DEMO_PURCHASE_URL = "http://buy.crimsonland.com"
DEMO_PURCHASE_SCREEN_LIMIT_MS = 16_000
DEMO_PURCHASE_INTERSTITIAL_LIMIT_MS = 10_000

_DEMO_PURCHASE_TITLE = "Upgrade to the full version of Crimsonland Today!"
_DEMO_PURCHASE_FEATURES_TITLE = "Full version features:"
_DEMO_PURCHASE_FEATURE_LINES: tuple[tuple[str, float], ...] = (
    ("-Unlimited Play Time in three thrilling Game Modes!", 22.0),
    ("-The varied weapon arsenal consisting of over 20 unique", 17.0),
    (" weapons that allow you to deal death with plasma, lead,", 17.0),
    (" fire and electricity!", 22.0),
    ("-Over 40 game altering Perks!", 22.0),
    ("-40 insane Levels that give you", 18.0),
    (" hours of intense and fun gameplay!", 22.0),
    ("-The ability to post your high scores online!", 44.0),
)
_DEMO_PURCHASE_FOOTER = "Purchasing the game is very easy and secure."


class _DemoLocalInputRuntime(LocalInputRuntime):
    view: DemoView

    def capture_frame_inputs(self, frame_ctx: FrameContext) -> list[PlayerInput]:
        return self.view._build_runner_inputs(frame_ctx)


def _weapon_name(weapon_id: WeaponId, *, preserve_bugs: bool = False) -> str:
    return weapon_display_name(weapon_id, preserve_bugs=bool(preserve_bugs))


class DemoView:
    """Attract-mode demo scaffold.

    Modeled after the classic demo helpers in crimsonland.exe:
      - demo_setup_variant_0 @ 0x00402ED0
      - demo_setup_variant_1 @ 0x004030F0
      - demo_setup_variant_2 @ 0x00402FE0
      - demo_setup_variant_3 @ 0x00403250
      - demo_mode_start       @ 0x00403390
    """

    def __init__(self, state: GameState) -> None:
        self.state = state
        self._runtime = WorldRuntime(
            assets_dir=state.assets_dir,
            world_size=float(WORLD_SIZE),
            demo_mode_active=True,
            hardcore=state.config.gameplay.hardcore,
            preserve_bugs=bool(state.preserve_bugs),
            config=state.config,
            audio=state.audio,
            audio_rng=state.rng,
        )
        self._runtime.reset()

        self._demo_targets: list[int | None] = []
        self._variant_index = 0
        self._demo_variant_index = 0
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        self._finished = False
        self._upsell_message_index = 0
        self._upsell_pulse_ms = 0
        self._upsell_font: GrimMonoFont | None = None
        self._purchase_active = False
        self._purchase_button = UiButtonState("Purchase", force_wide=True)
        self._maybe_later_button = UiButtonState("Maybe later", force_wide=True)
        self._tick_harness = StandaloneTickHarness(
            game_mode=GameMode.DEMO,
            input_runtime=_DemoLocalInputRuntime(view=self),
        )
        self._seed_from_app_state = True

    def _open_world_runtime(self) -> None:
        self._runtime.open_runtime()

    def _close_world_runtime(self) -> None:
        self._runtime.close_runtime()

    def _apply_terrain_setup(
        self,
        *,
        terrain_slots: TerrainSlotTriplet,
    ) -> None:
        terrain = advance_explicit_terrain(
            self._runtime.sim_world.state.rng,
            terrain_slots=terrain_slots,
            width=int(WORLD_SIZE),
            height=int(WORLD_SIZE),
        )
        self._runtime.terrain_runtime.apply_terrain_setup(
            terrain_slots=terrain.terrain_slots,
            seed=terrain.terrain_seed,
        )
        self._sync_audio_rng_from_runtime()

    def _sync_audio_rng_from_runtime(self) -> None:
        live_rng = self._runtime.sim_world.state.rng
        self._runtime.audio_rng = live_rng
        self._runtime.sync_audio_bridge_state()

    def _commit_live_rng_state_to_app(self) -> None:
        self.state.rng.srand(int(self._runtime.sim_world.state.rng.state))

    def _next_demo_reset_seed(self) -> int:
        if self._seed_from_app_state:
            self._seed_from_app_state = False
            return int(self.state.rng.state)
        return int(self._runtime.sim_world.state.rng.state)

    def _draw_world(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        self._runtime.renderer.draw(
            render_frame=self._runtime.build_render_frame(),
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def open(self) -> None:
        self._finished = False
        self._upsell_message_index = 0
        self._upsell_pulse_ms = 0
        self._purchase_active = False
        self._purchase_button = UiButtonState("Purchase", force_wide=True)
        self._maybe_later_button = UiButtonState("Maybe later", force_wide=True)
        self._variant_index = 0
        self._demo_variant_index = 0
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        self._open_world_runtime()
        self._demo_mode_start()

    def close(self) -> None:
        self._finished = True
        self._purchase_active = False
        if not self._seed_from_app_state:
            self._commit_live_rng_state_to_app()
        self._tick_harness.reset()
        self._close_world_runtime()
        self._upsell_font = None
        self._seed_from_app_state = True

    def is_finished(self) -> bool:
        return self._finished

    def update(self, dt: float) -> None:
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._finished:
            return
        frame_dt = min(dt, 0.1)
        frame_dt_ms = int(frame_dt * 1000.0)
        if frame_dt_ms <= 0:
            return

        if (
            (not self._purchase_active)
            and self.state.demo_enabled
            and self._purchase_screen_triggered()
        ):
            self._begin_purchase_screen(DEMO_PURCHASE_SCREEN_LIMIT_MS, reset_timeline=False)

        if self._purchase_active:
            self._upsell_pulse_ms += frame_dt_ms
            self._update_purchase_screen(frame_dt_ms)
            self._quest_spawn_timeline_ms += frame_dt_ms
            if self._quest_spawn_timeline_ms > self._demo_time_limit_ms:
                # demo_purchase_screen_update restarts the demo once the purchase screen
                # timer exceeds demo_time_limit_ms.
                self._demo_mode_start()
            return

        if self._skip_triggered():
            self._finished = True
            return

        self._quest_spawn_timeline_ms += frame_dt_ms
        self._update_world(frame_dt)
        self._sync_audio_rng_from_runtime()
        if self._quest_spawn_timeline_ms > self._demo_time_limit_ms:
            self._demo_mode_start()

    def draw(self) -> None:
        if self._finished:
            return
        if self._purchase_active:
            self._draw_purchase_screen()
            return
        self._draw_world()
        self._draw_overlay()

    def _skip_triggered(self) -> bool:
        if rl.get_key_pressed() != 0:
            return True
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            return True
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT):
            return True
        return False

    def _purchase_screen_triggered(self) -> bool:
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            return True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            return True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            return True
        return False

    def _begin_purchase_screen(self, limit_ms: int, *, reset_timeline: bool) -> None:
        self._purchase_active = True
        if reset_timeline:
            self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = max(0, int(limit_ms))
        self._purchase_button = UiButtonState("Purchase", force_wide=True)
        self._maybe_later_button = UiButtonState("Maybe later", force_wide=True)

    def _purchase_layout_wide_shift(self) -> float:
        screen_w = self.state.config.display.width
        if screen_w == 0x320:  # 800
            return 64.0
        if screen_w == 0x400:  # 1024
            return 128.0
        return 0.0

    def _trigger_purchase(self) -> None:
        self.state.quit_requested = True
        try:
            webbrowser.open(DEMO_PURCHASE_URL)
        except (OSError, webbrowser.Error):
            return

    def _update_purchase_screen(self, dt_ms: int) -> None:
        dt_ms = max(0, int(dt_ms))
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._purchase_active = False
            self._finished = True
            return

        resources = require_runtime_resources(self.state)

        w = float(self.state.config.display.width)
        h = float(self.state.config.display.height)
        wide_shift = self._purchase_layout_wide_shift()
        button_base_y = h / 2.0 + 102.0 + wide_shift * 0.3
        button_base_pos = Vec2(w / 2.0 + 128.0, button_base_y + 50.0)

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        scale = 1.0
        button_w = button_width(
            resources, self._purchase_button.label, scale=scale, force_wide=self._purchase_button.force_wide,
        )
        purchase_requested = button_update(
            self._purchase_button,
            pos=button_base_pos,
            width=float(button_w),
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        )

        if button_update(
            self._maybe_later_button,
            pos=button_base_pos.offset(dy=40.0),
            width=float(button_w),
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        ):
            self._purchase_active = False
            self._finished = True
            return

        # Keyboard activation for convenience; original uses UI mouse.
        purchase_requested = purchase_requested or rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER)
        if purchase_requested:
            self._trigger_purchase()

    def _draw_purchase_screen(self) -> None:
        rl.clear_background(rl.BLACK)

        resources = require_runtime_resources(self.state)
        backplasma = resources.texture(TextureId.BACKPLASMA)

        pulse_phase = float(self._upsell_pulse_ms % 1000)
        pulse = math.sin(pulse_phase * 6.2831855)
        pulse = pulse * pulse

        screen_w = float(self.state.config.display.width)
        screen_h = float(self.state.config.display.height)

        # demo_purchase_screen_update @ 0x0040b985:
        #   - full-screen quad
        #   - UV: 0..0.5 (top-left quarter of the backplasma atlas)
        #   - per-corner color slots, with a sin^2 pulse at bottom-right

        def _to_u8(value: float) -> int:
            return int(clamp(value, 0.0, 1.0) * 255.0 + 0.5)

        c0 = rl.Color(_to_u8(0.0), _to_u8(0.0), _to_u8(0.0), _to_u8(1.0))
        c1 = rl.Color(_to_u8(0.0), _to_u8(0.0), _to_u8(0.3), _to_u8(1.0))
        c2 = rl.Color(
            _to_u8(0.0),
            _to_u8(0.4),
            _to_u8(pulse * 0.55),
            _to_u8(pulse),
        )
        c3 = rl.Color(_to_u8(0.0), _to_u8(0.4), _to_u8(0.4), _to_u8(1.0))

        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
        rl.rl_set_texture(backplasma.id)
        rl.rl_begin(rd.RL_QUADS)
        # TL
        rl.rl_color4ub(c0.r, c0.g, c0.b, c0.a)
        rl.rl_tex_coord2f(0.0, 0.0)
        rl.rl_vertex2f(0.0, 0.0)
        # TR
        rl.rl_color4ub(c1.r, c1.g, c1.b, c1.a)
        rl.rl_tex_coord2f(0.5, 0.0)
        rl.rl_vertex2f(screen_w, 0.0)
        # BR
        rl.rl_color4ub(c2.r, c2.g, c2.b, c2.a)
        rl.rl_tex_coord2f(0.5, 0.5)
        rl.rl_vertex2f(screen_w, screen_h)
        # BL
        rl.rl_color4ub(c3.r, c3.g, c3.b, c3.a)
        rl.rl_tex_coord2f(0.0, 0.5)
        rl.rl_vertex2f(0.0, screen_h)
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_blend_mode()

        wide_shift = self._purchase_layout_wide_shift()

        # Mockup and logo textures.
        mockup = resources.texture(TextureId.MOCKUP)
        x = screen_w / 2.0 - 128.0 + wide_shift
        y = screen_h / 2.0 - 140.0
        dst = rl.Rectangle(x, y, 512.0, 256.0)
        src = rl.Rectangle(0.0, 0.0, float(mockup.width), float(mockup.height))
        rl.draw_texture_pro(mockup, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        cl_logo = resources.texture(TextureId.CL_LOGO)
        x = screen_w / 2.0 - 256.0
        y = screen_h / 2.0 - 200.0 - wide_shift * 0.4
        dst = rl.Rectangle(x, y, 512.0, 64.0)
        src = rl.Rectangle(0.0, 0.0, float(cl_logo.width), float(cl_logo.height))
        rl.draw_texture_pro(cl_logo, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        x_text = screen_w / 2.0 - 296.0 - wide_shift * 0.8
        y = screen_h / 2.0 - 104.0
        color = rl.Color(255, 255, 255, 255)
        small = resources.small_font
        draw_small_text(small, _DEMO_PURCHASE_TITLE, Vec2(x_text, y), color)
        y += 28.0
        draw_small_text(small, _DEMO_PURCHASE_FEATURES_TITLE, Vec2(x_text, y), color)

        underline_w = measure_small_text_width(small, _DEMO_PURCHASE_FEATURES_TITLE)
        rl.draw_rectangle_rec(rl.Rectangle(x_text, y + 15.0, underline_w, 2.0), rl.Color(255, 255, 255, 160))

        y += 22.0
        x_list = x_text + 8.0
        for line, delta_y in _DEMO_PURCHASE_FEATURE_LINES:
            draw_small_text(small, line, Vec2(x_list, y), color)
            y += delta_y
        draw_small_text(small, _DEMO_PURCHASE_FOOTER, Vec2(x_text, y), color)

        # Buttons on the right.
        button_base_y = screen_h / 2.0 + 102.0 + wide_shift * 0.3
        button_base_pos = Vec2(screen_w / 2.0 + 128.0, button_base_y + 50.0)
        scale = 1.0
        button_w = button_width(
            resources, self._purchase_button.label, scale=scale, force_wide=self._purchase_button.force_wide,
        )
        button_draw(resources, self._purchase_button, pos=button_base_pos, width=button_w, scale=scale)
        button_draw(
            resources,
            self._maybe_later_button,
            pos=button_base_pos.offset(dy=40.0),
            width=button_w,
            scale=scale,
        )

        # Demo purchase screen uses menu-style cursor; draw it explicitly since the OS cursor is hidden.
        particles = resources.texture(TextureId.PARTICLES)
        cursor_tex = resources.texture(TextureId.UI_CURSOR)
        mouse = rl.get_mouse_position()
        pulse_time = float(self._upsell_pulse_ms) * 0.001
        draw_menu_cursor(particles, cursor_tex, pos=Vec2.from_xy(mouse), pulse_time=pulse_time)

    def _demo_mode_start(self) -> None:
        index = self._demo_variant_index
        self._demo_variant_index = (index + 1) % DEMO_VARIANT_COUNT
        self._variant_index = index
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        self._purchase_active = False
        player_count = 2 if index in (0, 1, 4) else 1
        self._runtime.reset(seed=self._next_demo_reset_seed(), player_count=player_count)
        self._tick_harness.reset()
        self._sync_audio_rng_from_runtime()
        self._runtime.sim_world.state.bonuses.weapon_power_up = 0.0
        if index == 0:
            self._setup_variant_0()
        elif index == 1:
            self._setup_variant_1()
        elif index == 2:
            self._setup_variant_2()
        elif index == 3:
            self._setup_variant_3()
        elif index == 4:
            self._setup_variant_0()
        else:
            # demo_purchase_interstitial_begin
            self._begin_purchase_screen(DEMO_PURCHASE_INTERSTITIAL_LIMIT_MS, reset_timeline=True)

        # demo_purchase_screen_update increments demo_upsell_message_index when the
        # timeline resets (quest_spawn_timeline == 0) and the purchase screen is inactive.
        if (not self._purchase_active) and _DEMO_UPSELL_MESSAGES:
            self._upsell_message_index = (self._upsell_message_index + 1) % len(_DEMO_UPSELL_MESSAGES)
        self._sync_audio_rng_from_runtime()

    def _setup_world_players(self, specs: list[tuple[Vec2, int]]) -> None:
        for idx, (pos, weapon_id) in enumerate(specs):
            if idx >= len(self._runtime.sim_world.players):
                continue
            player = self._runtime.sim_world.players[idx]
            player.pos = pos
            # Keep aim anchored to the spawn position so demo aim starts stable.
            player.aim = pos
            weapon_assign_player(player, WeaponId(weapon_id), state=self._runtime.sim_world.state)
        self._demo_targets = [None] * len(self._runtime.sim_world.players)

    def _spawn(self, spawn_id: SpawnId, pos: Vec2, *, heading: float = 0.0) -> None:
        rng = self._runtime.sim_world.state.rng
        self._runtime.sim_world.creatures.spawn_template(
            spawn_id,
            pos,
            float(heading),
            rng,
        )

    def _setup_variant_0(self) -> None:
        self._demo_time_limit_ms = 4000
        # demo_setup_variant_0 uses weapon_id=0x0B.
        weapon_id = 11
        self._setup_world_players(
            [
                (Vec2(448.0, 384.0), weapon_id),
                (Vec2(546.0, 654.0), weapon_id),
            ],
        )
        y = 256
        i = 0
        while y < 1696:
            col = i % 2
            self._spawn(SpawnId.SPIDER_SP1_AI7_TIMER_38, Vec2(float((col + 2) * 64), float(y)), heading=RANDOM_HEADING_SENTINEL)
            self._spawn(SpawnId.SPIDER_SP1_AI7_TIMER_38, Vec2(float(col * 64 + 798), float(y)), heading=RANDOM_HEADING_SENTINEL)
            y += 80
            i += 1

    def _setup_variant_1(self) -> None:
        self._demo_time_limit_ms = 5000
        # demo_setup_variant_1 uses weapon_id=0x05.
        weapon_id = 5
        rng = self._runtime.sim_world.state.rng
        self._setup_world_players(
            [
                (Vec2(490.0, 448.0), weapon_id),
                (Vec2(480.0, 576.0), weapon_id),
            ],
        )
        # Native variant 1 calls terrain_generate(&quest_meta_terrain_desc_unlock_gt_0x13).
        self._apply_terrain_setup(terrain_slots=Q2_TERRAIN_SLOTS)
        self._runtime.sim_world.state.bonuses.weapon_power_up = 15.0
        for idx in range(20):
            x = float(
                int(
                    rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP1_X)
                    % 200,
                )
                + 32,
            )
            y = float(
                int(
                    rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP1_Y)
                    % 899,
                )
                + 64,
            )
            self._spawn(SpawnId.SPIDER_SP1_RANDOM_GREEN_34, Vec2(x, y), heading=RANDOM_HEADING_SENTINEL)
            if idx % 3 != 0:
                spawn_pos = Vec2(
                    float(
                        int(
                            rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP2_X)
                            % 30,
                        )
                        + 32,
                    ),
                    float(
                        int(
                            rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP2_Y)
                            % 899,
                        )
                        + 64,
                    ),
                )
                self._spawn(SpawnId.SPIDER_SP2_RANDOM_35, spawn_pos, heading=RANDOM_HEADING_SENTINEL)

    def _setup_variant_2(self) -> None:
        self._demo_time_limit_ms = 5000
        # demo_setup_variant_2 uses weapon_id=0x15.
        weapon_id = 21
        self._setup_world_players([(Vec2(512.0, 512.0), weapon_id)])
        y = 128
        i = 0
        while y < 848:
            col = i % 2
            self._spawn(SpawnId.ZOMBIE_RANDOM_41, Vec2(float(col * 64 + 32), float(y)), heading=RANDOM_HEADING_SENTINEL)
            self._spawn(SpawnId.ZOMBIE_RANDOM_41, Vec2(float((col + 2) * 64), float(y)), heading=RANDOM_HEADING_SENTINEL)
            self._spawn(SpawnId.ZOMBIE_RANDOM_41, Vec2(float(col * 64 - 64), float(y)), heading=RANDOM_HEADING_SENTINEL)
            self._spawn(SpawnId.ZOMBIE_RANDOM_41, Vec2(float((col + 12) * 64), float(y)), heading=RANDOM_HEADING_SENTINEL)
            y += 60
            i += 1

    def _setup_variant_3(self) -> None:
        self._demo_time_limit_ms = 4000
        # demo_setup_variant_3 uses weapon_id=0x12.
        weapon_id = 18
        rng = self._runtime.sim_world.state.rng
        self._setup_world_players([(Vec2(512.0, 512.0), weapon_id)])
        quest = quest_by_level(QuestLevel(1, 1))
        assert quest is not None
        # Native variant 3 calls terrain_generate(&quest_selected_meta), which is the
        # base of the quest metadata array in this build, so it resolves to quest 1.1.
        self._apply_terrain_setup(terrain_slots=quest.terrain_slots)
        for idx in range(20):
            x = float(
                int(
                    rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_BIG_X)
                    % 200,
                )
                + 32,
            )
            y = float(
                int(
                    rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_BIG_Y)
                    % 899,
                )
                + 64,
            )
            self._spawn(SpawnId.ALIEN_CONST_GREEN_24, Vec2(x, y), heading=0.0)
            if idx % 3 != 0:
                spawn_pos = Vec2(
                    float(
                        int(
                            rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_SMALL_X)
                            % 30,
                        )
                        + 32,
                    ),
                    float(
                        int(
                            rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_SMALL_Y)
                            % 899,
                        )
                        + 64,
                    ),
                )
                self._spawn(SpawnId.ALIEN_SMALL_GREEN_MAN_25, spawn_pos, heading=0.0)

    def _draw_overlay(self) -> None:
        if self.state.demo_enabled:
            self._draw_demo_upsell_overlay()
            return
        title = f"DEMO MODE  ({self._variant_index + 1}/{DEMO_VARIANT_COUNT})"
        hint = "Press any key / click to skip"
        remaining = max(0.0, float(self._demo_time_limit_ms - self._quest_spawn_timeline_ms) / 1000.0)
        weapons = ", ".join(
            f"P{p.index + 1}:{_weapon_name(p.weapon.weapon_id, preserve_bugs=bool(self.state.preserve_bugs))}"
            for p in self._runtime.sim_world.players
        )
        detail = f"{weapons}  —  next in {remaining:0.1f}s"
        rl.draw_text(title, 16, 12, 20, rl.Color(240, 240, 240, 255))
        rl.draw_text(detail, 16, 36, 16, rl.Color(180, 180, 190, 255))
        rl.draw_text(hint, 16, 56, 16, rl.Color(140, 140, 150, 255))

    def _ensure_upsell_font(self) -> GrimMonoFont:
        if self._upsell_font is not None:
            return self._upsell_font
        self._upsell_font = load_grim_mono_font(self.state.assets_dir)
        return self._upsell_font

    def _draw_demo_upsell_overlay(self) -> None:
        # Modeled after the shareware "Want more ..." overlay in demo_purchase_screen_update
        # (crimsonland.exe 0x0040B740), but without the purchase screen.
        if not _DEMO_UPSELL_MESSAGES:
            return

        font = self._ensure_upsell_font()
        msg = _DEMO_UPSELL_MESSAGES[self._upsell_message_index]

        timeline_ms = self._quest_spawn_timeline_ms
        limit_ms = self._demo_time_limit_ms
        var_2c = float(timeline_ms) * 0.016

        alpha = 1.0
        if var_2c < 20.0:
            alpha = var_2c * 0.05
        if timeline_ms > limit_ms - 500:
            alpha = float(limit_ms - timeline_ms) * 0.002
        alpha = clamp(alpha, 0.0, 1.0)

        scale = 0.8
        text_w = float(len(msg)) * 12.8

        text_x = 50.0
        text_y = var_2c + 50.0
        bg_x = 60.0
        bg_y = text_y - 4.0
        bar_x = 64.0
        bar_y = var_2c + 72.0

        bg_alpha = int(round(clamp(alpha * 0.5, 0.0, 1.0) * 255.0))
        bar_alpha = int(round(clamp(alpha * 0.8, 0.0, 1.0) * 255.0))
        txt_alpha = int(round(clamp(alpha, 0.0, 1.0) * 255.0))

        rl.draw_rectangle_rec(
            rl.Rectangle(bg_x, bg_y, text_w + 12.0, 30.0),
            rl.Color(0, 0, 0, bg_alpha),
        )

        progress = 0.0
        if limit_ms > 0:
            progress = clamp(float(timeline_ms) / float(limit_ms), 0.0, 1.0)
        rl.draw_rectangle_rec(
            rl.Rectangle(bar_x, bar_y, text_w * progress, 3.0),
            rl.Color(128, 26, 26, bar_alpha),
        )

        draw_grim_mono_text(font, msg, Vec2(text_x, text_y), scale, rl.Color(255, 255, 255, txt_alpha))

    def _build_runner_inputs(self, frame_ctx: FrameContext) -> list[PlayerInput]:
        return self._build_demo_inputs(float(frame_ctx.dt_seconds))

    def _update_world(self, dt: float) -> None:
        if not self._runtime.sim_world.players:
            return
        self._tick_harness.advance_frame(self._runtime, float(dt))

    def _build_demo_inputs(self, dt: float) -> list[PlayerInput]:
        players = self._runtime.sim_world.players
        creatures = self._runtime.sim_world.creatures.entries
        if len(self._demo_targets) != len(players):
            self._demo_targets = [None] * len(players)
        center = Vec2(float(self._runtime.world_size) * 0.5, float(self._runtime.world_size) * 0.5)

        dt = float(dt)

        def _turn_towards_heading(cur: float, target: float) -> tuple[float, float]:
            cur = cur % math.tau
            target = target % math.tau
            delta = (target - cur + math.pi) % math.tau - math.pi
            diff = abs(delta)
            if diff <= 1e-9:
                return cur, 0.0
            step = dt * diff * 5.0
            cur = (cur + step) % math.tau if delta > 0.0 else (cur - step) % math.tau
            return cur, diff

        inputs: list[PlayerInput] = []
        for idx, player in enumerate(players):
            target_idx = self._select_demo_target(idx, player, creatures)
            target = None
            if target_idx is not None and 0 <= target_idx < len(creatures):
                candidate = creatures[target_idx]
                if candidate.active and candidate.hp > 0.0:
                    target = candidate

            # Aim: ease the aim point toward the target.
            aim = player.aim
            auto_fire = False
            if target is not None:
                target_pos = target.pos
                aim_dir, aim_dist = (target_pos - aim).normalized_with_length()
                if aim_dist >= 4.0:
                    step = aim_dist * 6.0 * dt
                    aim += aim_dir * step
                else:
                    aim = target_pos
                auto_fire = aim_dist < 128.0
            else:
                away_from_center, amag = (player.pos - center).normalized_with_length()
                if amag <= 1e-6:
                    away_from_center = Vec2(0.0, -1.0)
                aim = player.pos + away_from_center * 60.0

            # Movement:
            # - orbit center if no target
            # - chase target when near center
            # - return to center when too far
            if target is None:
                move_delta = (player.pos - center).rotated(math.pi / 2.0)
            else:
                center_dist = (player.pos - center).length()
                if center_dist <= 300.0:
                    move_delta = target.pos - player.pos
                else:
                    move_delta = center - player.pos

            desired_dir, desired_mag = move_delta.normalized_with_length()
            if desired_mag <= 1e-6:
                move = Vec2()
            else:
                desired_heading = desired_dir.to_heading()
                smoothed_heading, angle_diff = _turn_towards_heading(float(player.heading), desired_heading)
                move_mag = max(0.001, (math.pi - angle_diff) / math.pi)
                move = Vec2.from_heading(smoothed_heading) * move_mag

            inputs.append(
                PlayerInput(
                    move=move,
                    aim=aim,
                    fire_down=auto_fire,
                    fire_pressed=auto_fire,
                    reload_pressed=False,
                ),
            )

        return inputs

    def _nearest_world_creature_index(self, pos: Vec2) -> int | None:
        best_idx = None
        best_dist = 0.0
        for idx, creature in enumerate(self._runtime.sim_world.creatures.entries):
            if not (creature.active and creature.hp > 0.0):
                continue
            d = Vec2.distance_sq(pos, creature.pos)
            if best_idx is None or d < best_dist:
                best_idx = idx
                best_dist = d
        return best_idx

    def _select_demo_target(self, player_index: int, player: PlayerState, creatures: list) -> int | None:
        candidate = self._nearest_world_creature_index(player.pos)
        current = self._demo_targets[player_index] if player_index < len(self._demo_targets) else None
        if current is None:
            self._demo_targets[player_index] = candidate
            return candidate
        if not (0 <= current < len(creatures)):
            self._demo_targets[player_index] = candidate
            return candidate
        current_creature = creatures[current]
        if current_creature.hp <= 0.0 or not current_creature.active:
            self._demo_targets[player_index] = candidate
            return candidate
        if candidate is None or candidate == current:
            return current
        cand_creature = creatures[candidate]
        if not cand_creature.active or cand_creature.hp <= 0.0:
            return current
        cur_d = (current_creature.pos - player.pos).length()
        cand_d = (cand_creature.pos - player.pos).length()
        if cand_d + 64.0 < cur_d:
            self._demo_targets[player_index] = candidate
            return candidate
        return current
