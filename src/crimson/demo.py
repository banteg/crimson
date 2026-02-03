from __future__ import annotations

import math
from pathlib import Path
import random
from typing import Protocol

import pyray as rl

from grim.audio import AudioState, update_audio
from grim.assets import PaqTextureCache, load_paq_entries
from grim.config import CrimsonConfig
from grim.fonts.grim_mono import GrimMonoFont, draw_grim_mono_text, load_grim_mono_font
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from grim.rand import Crand
from .game_world import GameWorld
from .gameplay import PlayerInput, PlayerState, weapon_assign_player
from .ui.cursor import draw_menu_cursor
from .ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from .weapons import WEAPON_TABLE, WeaponId, projectile_type_id_from_weapon_id, weapon_entry_for_projectile_type_id

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


class DemoState(Protocol):
    assets_dir: Path
    rng: random.Random
    config: CrimsonConfig
    texture_cache: PaqTextureCache | None
    audio: AudioState | None


def _weapon_name(weapon_id: int) -> str:
    for weapon in WEAPON_TABLE:
        if weapon.weapon_id == weapon_id:
            return weapon.name or f"weapon_{weapon_id}"
    return f"weapon_{weapon_id}"


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _distance_sq(x0: float, y0: float, x1: float, y1: float) -> float:
    dx = x1 - x0
    dy = y1 - y0
    return dx * dx + dy * dy


def _normalize(dx: float, dy: float) -> tuple[float, float, float]:
    d = math.hypot(dx, dy)
    if d <= 1e-6:
        return 0.0, 0.0, 0.0
    inv = 1.0 / d
    return dx * inv, dy * inv, d


class DemoView:
    """Attract-mode demo scaffold.

    Modeled after the classic demo helpers in crimsonland.exe:
      - demo_setup_variant_0 @ 0x00402ED0
      - demo_setup_variant_1 @ 0x004030F0
      - demo_setup_variant_2 @ 0x00402FE0
      - demo_setup_variant_3 @ 0x00403250
      - demo_mode_start       @ 0x00403390
    """

    def __init__(self, state: DemoState) -> None:
        self._state = state
        self._world = GameWorld(
            assets_dir=state.assets_dir,
            world_size=WORLD_SIZE,
            demo_mode_active=True,
            hardcore=bool(int(state.config.data.get("hardcore_flag", 0) or 0)),
            difficulty_level=0,
            texture_cache=state.texture_cache,
            config=state.config,
            audio=state.audio,
            audio_rng=state.rng,
        )
        self._crand = Crand(0)
        self._demo_targets: list[int | None] = []
        self._variant_index = 0
        self._demo_variant_index = 0
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        self._finished = False
        self._upsell_message_index = 0
        self._upsell_pulse_ms = 0
        self._upsell_font: GrimMonoFont | None = None
        self._small_font: SmallFontData | None = None
        self._purchase_active = False
        self._purchase_url_opened = False
        self._purchase_button = UiButtonState("Purchase", force_wide=True)
        self._maybe_later_button = UiButtonState("Maybe later", force_wide=True)
        self._spawn_rng = Crand(0)

    def open(self) -> None:
        self._finished = False
        self._upsell_message_index = 0
        self._upsell_pulse_ms = 0
        self._purchase_active = False
        self._purchase_url_opened = False
        self._purchase_button = UiButtonState("Purchase", force_wide=True)
        self._maybe_later_button = UiButtonState("Maybe later", force_wide=True)
        self._variant_index = 0
        self._demo_variant_index = 0
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        self._crand.srand(self._state.rng.getrandbits(32))
        self._world.open()
        self._demo_mode_start()

    def close(self) -> None:
        self._world.close()
        if self._upsell_font is not None:
            rl.unload_texture(self._upsell_font.texture)
            self._upsell_font = None
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None

    def is_finished(self) -> bool:
        return self._finished

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._finished:
            return
        frame_dt = min(dt, 0.1)
        frame_dt_ms = int(frame_dt * 1000.0)
        if frame_dt_ms <= 0:
            return

        if (not self._purchase_active) and getattr(self._state, "demo_enabled", False) and self._purchase_screen_triggered():
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
        if self._quest_spawn_timeline_ms > self._demo_time_limit_ms:
            self._demo_mode_start()

    def draw(self) -> None:
        if self._purchase_active:
            self._draw_purchase_screen()
            return
        self._world.draw()
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
        self._purchase_url_opened = False
        self._purchase_button = UiButtonState("Purchase", force_wide=True)
        self._maybe_later_button = UiButtonState("Maybe later", force_wide=True)

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _purchase_var_28_2(self) -> float:
        screen_w = int(self._state.config.screen_width)
        if screen_w == 0x320:  # 800
            return 64.0
        if screen_w == 0x400:  # 1024
            return 128.0
        return 0.0

    def _update_purchase_screen(self, dt_ms: int) -> None:
        dt_ms = max(0, int(dt_ms))
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._purchase_active = False
            self._finished = True
            return

        font = self._ensure_small_font()
        cache = self._ensure_cache()
        textures = UiButtonTextureSet(
            button_sm=cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture,
            button_md=cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture,
        )
        if textures.button_sm is None and textures.button_md is None:
            return

        w = float(self._state.config.screen_width)
        h = float(self._state.config.screen_height)
        wide_shift = self._purchase_var_28_2()
        button_x = w / 2.0 + 128.0
        button_base_y = h / 2.0 + 102.0 + wide_shift * 0.3
        purchase_y = button_base_y + 50.0
        maybe_y = button_base_y + 90.0

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        scale = 1.0
        button_w = button_width(font, self._purchase_button.label, scale=scale, force_wide=self._purchase_button.force_wide)
        if button_update(
            self._purchase_button,
            x=float(button_x),
            y=float(purchase_y),
            width=float(button_w),
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        ):
            if not self._purchase_url_opened:
                self._purchase_url_opened = True
                try:
                    import webbrowser

                    webbrowser.open(DEMO_PURCHASE_URL)
                except Exception:
                    pass
            if hasattr(self._state, "quit_requested"):
                self._state.quit_requested = True

        if button_update(
            self._maybe_later_button,
            x=float(button_x),
            y=float(maybe_y),
            width=float(button_w),
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        ):
            self._purchase_active = False
            self._finished = True
            return

        # Keyboard activation for convenience; original uses UI mouse.
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            if not self._purchase_url_opened:
                self._purchase_url_opened = True
                try:
                    import webbrowser

                    webbrowser.open(DEMO_PURCHASE_URL)
                except Exception:
                    pass
            if hasattr(self._state, "quit_requested"):
                self._state.quit_requested = True

        # Keep referenced to avoid unused warnings if this method grows.
        _ = textures

    def _draw_purchase_screen(self) -> None:
        rl.clear_background(rl.BLACK)

        logos = getattr(self._state, "logos", None)
        if logos is None or logos.backplasma.texture is None:
            return
        backplasma = logos.backplasma.texture

        pulse_phase = float(self._upsell_pulse_ms % 1000)
        pulse = math.sin(pulse_phase * 6.2831855)
        pulse = pulse * pulse

        screen_w = float(self._state.config.screen_width)
        screen_h = float(self._state.config.screen_height)

        # demo_purchase_screen_update @ 0x0040b985:
        #   - full-screen quad
        #   - UV: 0..0.5 (top-left quarter of the backplasma atlas)
        #   - per-corner color slots, with a sin^2 pulse at bottom-right

        def _to_u8(value: float) -> int:
            return int(_clamp(value, 0.0, 1.0) * 255.0 + 0.5)

        c0 = rl.Color(_to_u8(0.0), _to_u8(0.0), _to_u8(0.0), _to_u8(1.0))
        c1 = rl.Color(_to_u8(0.0), _to_u8(0.0), _to_u8(0.3), _to_u8(1.0))
        c2 = rl.Color(
            _to_u8(0.0),
            _to_u8(0.4),
            _to_u8(pulse * 0.55),
            _to_u8(pulse),
        )
        c3 = rl.Color(_to_u8(0.0), _to_u8(0.4), _to_u8(0.4), _to_u8(1.0))

        rl.begin_blend_mode(rl.BLEND_ALPHA)
        rl.rl_set_texture(backplasma.id)
        rl.rl_begin(rl.RL_QUADS)
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

        wide_shift = self._purchase_var_28_2()

        # Mockup and logo textures.
        if logos.mockup.texture is not None:
            mockup = logos.mockup.texture
            x = screen_w / 2.0 - 128.0 + wide_shift
            y = screen_h / 2.0 - 140.0
            dst = rl.Rectangle(x, y, 512.0, 256.0)
            src = rl.Rectangle(0.0, 0.0, float(mockup.width), float(mockup.height))
            rl.draw_texture_pro(mockup, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        if logos.cl_logo.texture is not None:
            cl_logo = logos.cl_logo.texture
            x = screen_w / 2.0 - 256.0
            y = screen_h / 2.0 - 200.0 - wide_shift * 0.4
            dst = rl.Rectangle(x, y, 512.0, 64.0)
            src = rl.Rectangle(0.0, 0.0, float(cl_logo.width), float(cl_logo.height))
            rl.draw_texture_pro(cl_logo, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        small = self._ensure_small_font()
        text_scale = 1.2
        x_text = screen_w / 2.0 - 296.0 - wide_shift * 0.8
        y = screen_h / 2.0 - 104.0
        color = rl.Color(255, 255, 255, 255)
        draw_small_text(small, _DEMO_PURCHASE_TITLE, x_text, y, text_scale, color)
        y += 28.0
        draw_small_text(small, _DEMO_PURCHASE_FEATURES_TITLE, x_text, y, text_scale, color)

        underline_w = measure_small_text_width(small, _DEMO_PURCHASE_FEATURES_TITLE, text_scale)
        rl.draw_rectangle_rec(rl.Rectangle(x_text, y + 15.0, underline_w, 2.0), rl.Color(255, 255, 255, 160))

        y += 22.0
        x_list = x_text + 8.0
        for line, delta_y in _DEMO_PURCHASE_FEATURE_LINES:
            draw_small_text(small, line, x_list, y, text_scale, color)
            y += delta_y
        draw_small_text(small, _DEMO_PURCHASE_FOOTER, x_text, y, text_scale, color)

        # Buttons on the right.
        cache = self._ensure_cache()
        textures = UiButtonTextureSet(
            button_sm=cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture,
            button_md=cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture,
        )
        if textures.button_sm is None and textures.button_md is None:
            return

        button_x = screen_w / 2.0 + 128.0
        button_base_y = screen_h / 2.0 + 102.0 + wide_shift * 0.3
        purchase_y = button_base_y + 50.0
        maybe_y = button_base_y + 90.0
        scale = 1.0
        button_w = button_width(small, self._purchase_button.label, scale=scale, force_wide=self._purchase_button.force_wide)
        button_draw(textures, small, self._purchase_button, x=button_x, y=purchase_y, width=button_w, scale=scale)
        button_draw(textures, small, self._maybe_later_button, x=button_x, y=maybe_y, width=button_w, scale=scale)

        # Demo purchase screen uses menu-style cursor; draw it explicitly since the OS cursor is hidden.
        particles = cache.get_or_load("particles", "game/particles.jaz").texture
        cursor_tex = cache.get_or_load("ui_cursor", "ui/ui_cursor.jaz").texture
        pulse_time = float(self._upsell_pulse_ms) * 0.001
        draw_menu_cursor(particles, cursor_tex, x=float(mouse.x), y=float(mouse.y), pulse_time=pulse_time)

    def _ensure_cache(self) -> PaqTextureCache:
        cache = self._state.texture_cache
        if cache is not None:
            return cache
        entries = load_paq_entries(self._state.assets_dir)
        cache = PaqTextureCache(entries=entries, textures={})
        self._state.texture_cache = cache
        return cache

    def _demo_mode_start(self) -> None:
        index = self._demo_variant_index
        self._demo_variant_index = (index + 1) % DEMO_VARIANT_COUNT
        self._variant_index = index
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        self._purchase_active = False
        self._purchase_url_opened = False
        self._spawn_rng.srand(self._state.rng.randrange(0, 0x1_0000_0000))
        self._world.state.bonuses.weapon_power_up = 0.0
        if index == 0:
            self._apply_variant_ground(0)
            self._setup_variant_0()
        elif index == 1:
            self._apply_variant_ground(1)
            self._setup_variant_1()
        elif index == 2:
            self._apply_variant_ground(2)
            self._setup_variant_2()
        elif index == 3:
            self._apply_variant_ground(3)
            self._setup_variant_3()
        elif index == 4:
            self._apply_variant_ground(4)
            self._setup_variant_0()
        else:
            # demo_purchase_interstitial_begin
            self._begin_purchase_screen(DEMO_PURCHASE_INTERSTITIAL_LIMIT_MS, reset_timeline=True)

        # demo_purchase_screen_update increments demo_upsell_message_index when the
        # timeline resets (quest_spawn_timeline == 0) and the purchase screen is inactive.
        if (not self._purchase_active) and _DEMO_UPSELL_MESSAGES:
            self._upsell_message_index = (self._upsell_message_index + 1) % len(_DEMO_UPSELL_MESSAGES)

    def _setup_world_players(self, specs: list[tuple[float, float, int]]) -> None:
        seed = int(self._state.rng.getrandbits(32))
        self._world.reset(seed=seed, player_count=len(specs))
        for idx, (x, y, weapon_id) in enumerate(specs):
            if idx >= len(self._world.players):
                continue
            player = self._world.players[idx]
            player.pos_x = float(x)
            player.pos_y = float(y)
            # Keep aim anchored to the spawn position so demo aim starts stable.
            player.aim_x = float(x)
            player.aim_y = float(y)
            weapon_assign_player(player, int(weapon_id))
        self._demo_targets = [None] * len(self._world.players)

    def _apply_variant_ground(self, index: int) -> None:
        if index == 5:
            return
        terrain = {
            0: (
                "ter_q1_base",
                "ter_q1_tex1",
                "ter/ter_q1_base.jaz",
                "ter/ter_q1_tex1.jaz",
            ),
            1: (
                "ter_q2_base",
                "ter_q2_tex1",
                "ter/ter_q2_base.jaz",
                "ter/ter_q2_tex1.jaz",
            ),
            2: (
                "ter_q3_base",
                "ter_q3_tex1",
                "ter/ter_q3_base.jaz",
                "ter/ter_q3_tex1.jaz",
            ),
            3: (
                "ter_q4_base",
                "ter_q4_tex1",
                "ter/ter_q4_base.jaz",
                "ter/ter_q4_tex1.jaz",
            ),
            4: (
                "ter_q1_base",
                "ter_q1_tex1",
                "ter/ter_q1_base.jaz",
                "ter/ter_q1_tex1.jaz",
            ),
        }.get(
            index,
            (
                "ter_q1_base",
                "ter_q1_tex1",
                "ter/ter_q1_base.jaz",
                "ter/ter_q1_tex1.jaz",
            ),
        )
        base_key, overlay_key, base_path, overlay_path = terrain
        self._world.set_terrain(
            base_key=base_key,
            overlay_key=overlay_key,
            base_path=base_path,
            overlay_path=overlay_path,
        )

    def _wrap_pos(self, x: float, y: float) -> tuple[float, float]:
        return (x % WORLD_SIZE, y % WORLD_SIZE)

    def _crand_mod(self, mod: int) -> int:
        if mod <= 0:
            return 0
        return int(self._crand.rand() % mod)

    def _spawn(self, spawn_id: int, x: float, y: float, *, heading: float = 0.0) -> None:
        x, y = self._wrap_pos(x, y)
        detail_preset = 5
        if self._world.config is not None:
            detail_preset = int(self._world.config.data.get("detail_preset", 5) or 5)
        self._world.creatures.spawn_template(
            int(spawn_id),
            (x, y),
            float(heading),
            self._spawn_rng,
            rand=self._spawn_rng.rand,
            state=self._world.state,
            detail_preset=detail_preset,
        )

    def _setup_variant_0(self) -> None:
        self._demo_time_limit_ms = 4000
        # demo_setup_variant_0 uses weapon_id=0x0B.
        weapon_id = 11
        self._setup_world_players(
            [
                (448.0, 384.0, weapon_id),
                (546.0, 654.0, weapon_id),
            ]
        )
        y = 256
        i = 0
        while y < 1696:
            col = i % 2
            self._spawn(0x38, float((col + 2) * 64), float(y), heading=-100.0)
            self._spawn(0x38, float(col * 64 + 798), float(y), heading=-100.0)
            y += 80
            i += 1

    def _setup_variant_1(self) -> None:
        self._demo_time_limit_ms = 5000
        # demo_setup_variant_1 uses weapon_id=0x05.
        weapon_id = 5
        self._setup_world_players(
            [
                (490.0, 448.0, weapon_id),
                (480.0, 576.0, weapon_id),
            ]
        )
        self._world.state.bonuses.weapon_power_up = 15.0
        for idx in range(20):
            x = float(self._crand_mod(200) + 32)
            y = float(self._crand_mod(899) + 64)
            self._spawn(0x34, x, y, heading=-100.0)
            if idx % 3 != 0:
                x2 = float(self._crand_mod(30) + 32)
                y2 = float(self._crand_mod(899) + 64)
                self._spawn(0x35, x2, y2, heading=-100.0)

    def _setup_variant_2(self) -> None:
        self._demo_time_limit_ms = 5000
        # demo_setup_variant_2 uses weapon_id=0x15.
        weapon_id = 21
        self._setup_world_players([(512.0, 512.0, weapon_id)])
        y = 128
        i = 0
        while y < 848:
            col = i % 2
            self._spawn(0x41, float(col * 64 + 32), float(y), heading=-100.0)
            self._spawn(0x41, float((col + 2) * 64), float(y), heading=-100.0)
            self._spawn(0x41, float(col * 64 - 64), float(y), heading=-100.0)
            self._spawn(0x41, float((col + 12) * 64), float(y), heading=-100.0)
            y += 60
            i += 1

    def _setup_variant_3(self) -> None:
        self._demo_time_limit_ms = 4000
        # demo_setup_variant_3 uses weapon_id=0x12.
        weapon_id = 18
        self._setup_world_players([(512.0, 512.0, weapon_id)])
        for idx in range(20):
            x = float(self._crand_mod(200) + 32)
            y = float(self._crand_mod(899) + 64)
            self._spawn(0x24, x, y, heading=0.0)
            if idx % 3 != 0:
                x2 = float(self._crand_mod(30) + 32)
                y2 = float(self._crand_mod(899) + 64)
                self._spawn(0x25, x2, y2, heading=0.0)

    def _world_params(self) -> tuple[float, float, float, float]:
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w = float(self._state.config.screen_width)
        screen_h = float(self._state.config.screen_height)
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE

        cam_x = self._camera_x
        cam_y = self._camera_y
        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        if cam_x > -1.0:
            cam_x = -1.0
        if cam_y > -1.0:
            cam_y = -1.0
        if cam_x < min_x:
            cam_x = min_x
        if cam_y < min_y:
            cam_y = min_y

        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        return cam_x, cam_y, scale_x, scale_y

    def _world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        return (x + cam_x) * scale_x, (y + cam_y) * scale_y

    def _select_frame(self, spawn_id: int, phase: float) -> tuple[int, bool]:
        template = SPAWN_ID_TO_TEMPLATE.get(spawn_id)
        if template is None or template.type_id is None:
            return 0, False
        info = _TYPE_ANIM.get(template.type_id)
        if info is None:
            return 0, False
        flags = template.flags or CreatureFlags(0)
        frame, mirror_applied, _ = creature_anim_select_frame(
            phase,
            base_frame=info.base,
            mirror_long=info.mirror,
            flags=flags,
        )
        return frame, mirror_applied

    def _draw_fx(self) -> None:
        projectiles = self._projectile_pool.iter_active()
        secondary = self._secondary_projectile_pool.iter_active()
        if not (projectiles or secondary or self._beams or self._explosions):
            return
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        del cam_x, cam_y
        scale = (scale_x + scale_y) * 0.5

        for proj in projectiles:
            sx, sy = self._world_to_screen(proj.pos_x, proj.pos_y)
            base_radius = {
                0x05: 6.0,  # gauss
                0x0B: 10.0,  # rocket launcher
                0x15: 7.0,  # ion minigun beam seed
            }.get(proj.type_id, 5.0)
            radius = max(1.0, base_radius * scale)
            color = {
                0x05: rl.Color(235, 235, 235, 255),
                0x0B: rl.Color(255, 120, 80, 255),
                0x15: rl.Color(120, 220, 255, 255),
            }.get(proj.type_id, rl.Color(235, 235, 235, 255))
            rl.draw_circle(int(sx), int(sy), radius, color)

        for proj in secondary:
            sx, sy = self._world_to_screen(proj.pos_x, proj.pos_y)
            if proj.type_id == 4:
                radius = max(1.0, 12.0 * scale)
                rl.draw_circle(int(sx), int(sy), radius, rl.Color(200, 120, 255, 255))
                continue
            if proj.type_id == 3:
                t = _clamp(proj.vel_x, 0.0, 1.0)
                radius = proj.vel_y * t * 80.0
                alpha = int((1.0 - t) * 180.0)
                color = rl.Color(200, 120, 255, alpha)
                rl.draw_circle_lines(int(sx), int(sy), max(1.0, radius * scale), color)

        for beam in self._beams:
            x0, y0 = self._world_to_screen(beam.x0, beam.y0)
            x1, y1 = self._world_to_screen(beam.x1, beam.y1)
            alpha = int(_clamp(beam.life / 0.08, 0.0, 1.0) * 255.0)
            color = rl.Color(120, 220, 255, alpha)
            rl.draw_line_ex(rl.Vector2(x0, y0), rl.Vector2(x1, y1), 2.0 * scale, color)

        for fx in self._explosions:
            t = fx.elapsed / fx.duration if fx.duration > 0 else 1.0
            radius = fx.max_radius * _clamp(t, 0.0, 1.0)
            sx, sy = self._world_to_screen(fx.x, fx.y)
            alpha = int((1.0 - _clamp(t, 0.0, 1.0)) * 180.0)
            color = rl.Color(255, 180, 100, alpha) if fx.kind == "rocket" else rl.Color(200, 120, 255, alpha)
            rl.draw_circle_lines(int(sx), int(sy), max(1.0, radius * scale), color)

    def _draw_entities(self) -> None:
        cache = self._state.texture_cache
        if cache is None:
            return
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        del cam_x, cam_y

        player_tex = cache.get_or_load("trooper", "game/trooper.jaz").texture
        if player_tex is not None:
            for player in self._players:
                self._draw_sprite(
                    player_tex,
                    CreatureTypeId.TROOPER,
                    CreatureFlags(0),
                    player.phase,
                    player.x,
                    player.y,
                    scale_x,
                    scale_y,
                    tint=rl.Color(240, 240, 255, 255),
                )

        for creature in self._creatures:
            type_id = creature.type_id
            if type_id is None:
                continue
            asset = _TYPE_ASSET.get(type_id)
            if asset is None:
                continue
            texture = cache.texture(asset)
            if texture is None:
                rel_path = f"game/{asset}.jaz"
                texture = cache.get_or_load(asset, rel_path).texture
            if texture is None:
                continue
            flags = creature.flags

            def _to_u8(value: float) -> int:
                return int(_clamp(value, 0.0, 1.0) * 255.0 + 0.5)

            tint = rl.WHITE
            if creature.tint is not None and any(v is not None for v in creature.tint):
                tint_r, tint_g, tint_b, tint_a = resolve_tint(creature.tint)
                tint = rl.Color(
                    _to_u8(tint_r),
                    _to_u8(tint_g),
                    _to_u8(tint_b),
                    _to_u8(tint_a),
                )
            self._draw_sprite(
                texture,
                type_id,
                flags,
                creature.anim_phase,
                creature.x,
                creature.y,
                scale_x,
                scale_y,
                tint=tint,
                size_scale=_clamp(creature.size / 64.0, 0.25, 2.0),
            )

    def _draw_sprite(
        self,
        texture: rl.Texture2D,
        type_id: CreatureTypeId,
        flags: CreatureFlags,
        phase: float,
        world_x: float,
        world_y: float,
        scale_x: float,
        scale_y: float,
        *,
        tint: rl.Color,
        size_scale: float = 1.0,
    ) -> None:
        info = _TYPE_ANIM.get(type_id)
        if info is None:
            return
        frame, _, _ = creature_anim_select_frame(
            phase,
            base_frame=info.base,
            mirror_long=info.mirror,
            flags=flags,
        )

        grid = 8
        cell = float(texture.width) / grid if grid > 0 else float(texture.width)
        row = frame // grid
        col = frame % grid
        src = rl.Rectangle(float(col * cell), float(row * cell), float(cell), float(cell))
        screen_x, screen_y = self._world_to_screen(world_x, world_y)
        width = cell * scale_x * size_scale
        height = cell * scale_y * size_scale
        dst = rl.Rectangle(screen_x, screen_y, width, height)
        origin = rl.Vector2(width * 0.5, height * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, 0.0, tint)

    def _draw_overlay(self) -> None:
        if getattr(self._state, "demo_enabled", False):
            self._draw_demo_upsell_overlay()
            return
        title = f"DEMO MODE  ({self._variant_index + 1}/{DEMO_VARIANT_COUNT})"
        hint = "Press any key / click to skip"
        remaining = max(0.0, float(self._demo_time_limit_ms - self._quest_spawn_timeline_ms) / 1000.0)
        weapons = ", ".join(f"P{p.index + 1}:{_weapon_name(p.weapon_id)}" for p in self._world.players)
        detail = f"{weapons}  —  next in {remaining:0.1f}s"
        rl.draw_text(title, 16, 12, 20, rl.Color(240, 240, 240, 255))
        rl.draw_text(detail, 16, 36, 16, rl.Color(180, 180, 190, 255))
        rl.draw_text(hint, 16, 56, 16, rl.Color(140, 140, 150, 255))

    def _ensure_upsell_font(self) -> GrimMonoFont:
        if self._upsell_font is not None:
            return self._upsell_font
        missing_assets: list[str] = []
        self._upsell_font = load_grim_mono_font(self._state.assets_dir, missing_assets)
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
        alpha = _clamp(alpha, 0.0, 1.0)

        scale = 0.8
        text_w = float(len(msg)) * 12.8

        text_x = 50.0
        text_y = var_2c + 50.0
        bg_x = 60.0
        bg_y = text_y - 4.0
        bar_x = 64.0
        bar_y = var_2c + 72.0

        bg_alpha = int(round(_clamp(alpha * 0.5, 0.0, 1.0) * 255.0))
        bar_alpha = int(round(_clamp(alpha * 0.8, 0.0, 1.0) * 255.0))
        txt_alpha = int(round(_clamp(alpha, 0.0, 1.0) * 255.0))

        rl.draw_rectangle_rec(
            rl.Rectangle(bg_x, bg_y, text_w + 12.0, 30.0),
            rl.Color(0, 0, 0, bg_alpha),
        )

        progress = 0.0
        if limit_ms > 0:
            progress = _clamp(float(timeline_ms) / float(limit_ms), 0.0, 1.0)
        rl.draw_rectangle_rec(
            rl.Rectangle(bar_x, bar_y, text_w * progress, 3.0),
            rl.Color(128, 26, 26, bar_alpha),
        )

        draw_grim_mono_text(font, msg, text_x, text_y, scale, rl.Color(255, 255, 255, txt_alpha))

    def _update_world(self, dt: float) -> None:
        if not self._world.players:
            return
        inputs = self._build_demo_inputs(dt)
        self._world.update(dt, inputs=inputs, auto_pick_perks=False, game_mode=0, perk_progression_enabled=False)

    def _build_demo_inputs(self, dt: float) -> list[PlayerInput]:
        players = self._world.players
        creatures = self._world.creatures.entries
        if len(self._demo_targets) != len(players):
            self._demo_targets = [None] * len(players)
        center_x = float(self._world.world_size) * 0.5
        center_y = float(self._world.world_size) * 0.5

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
            aim_x = float(player.aim_x)
            aim_y = float(player.aim_y)
            auto_fire = False
            if target is not None:
                aim_dx = float(target.x) - aim_x
                aim_dy = float(target.y) - aim_y
                aim_dir_x, aim_dir_y, aim_dist = _normalize(aim_dx, aim_dy)
                if aim_dist >= 4.0:
                    step = aim_dist * 6.0 * dt
                    aim_x += aim_dir_x * step
                    aim_y += aim_dir_y * step
                else:
                    aim_x = float(target.x)
                    aim_y = float(target.y)
                auto_fire = aim_dist < 128.0
            else:
                ax, ay, amag = _normalize(float(player.pos_x) - center_x, float(player.pos_y) - center_y)
                if amag <= 1e-6:
                    ax, ay = 0.0, -1.0
                aim_x = float(player.pos_x) + ax * 60.0
                aim_y = float(player.pos_y) + ay * 60.0

            # Movement:
            # - orbit center if no target
            # - chase target when near center
            # - return to center when too far
            if target is None:
                move_dx = -(float(player.pos_y) - center_y)
                move_dy = float(player.pos_x) - center_x
            else:
                center_dist = math.hypot(float(player.pos_x) - center_x, float(player.pos_y) - center_y)
                if center_dist <= 300.0:
                    move_dx = float(target.x) - float(player.pos_x)
                    move_dy = float(target.y) - float(player.pos_y)
                else:
                    move_dx = center_x - float(player.pos_x)
                    move_dy = center_y - float(player.pos_y)

            desired_x, desired_y, desired_mag = _normalize(move_dx, move_dy)
            if desired_mag <= 1e-6:
                move_x = 0.0
                move_y = 0.0
            else:
                desired_heading = math.atan2(desired_y, desired_x) + math.pi / 2.0
                smoothed_heading, angle_diff = _turn_towards_heading(float(player.heading), desired_heading)
                move_mag = max(0.001, (math.pi - angle_diff) / math.pi)
                move_x = math.cos(smoothed_heading - math.pi / 2.0) * move_mag
                move_y = math.sin(smoothed_heading - math.pi / 2.0) * move_mag

            inputs.append(
                PlayerInput(
                    move_x=move_x,
                    move_y=move_y,
                    aim_x=aim_x,
                    aim_y=aim_y,
                    fire_down=auto_fire,
                    fire_pressed=auto_fire,
                    reload_pressed=False,
                )
            )

        return inputs

    def _nearest_world_creature_index(self, x: float, y: float) -> int | None:
        best_idx = None
        best_dist = 0.0
        for idx, creature in enumerate(self._world.creatures.entries):
            if not (creature.active and creature.hp > 0.0):
                continue
            d = _distance_sq(x, y, creature.x, creature.y)
            if best_idx is None or d < best_dist:
                best_idx = idx
                best_dist = d
        return best_idx

    def _select_demo_target(self, player_index: int, player: PlayerState, creatures: list) -> int | None:
        candidate = self._nearest_world_creature_index(player.pos_x, player.pos_y)
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
        cur_d = math.hypot(current_creature.x - player.pos_x, current_creature.y - player.pos_y)
        cand_d = math.hypot(cand_creature.x - player.pos_x, cand_creature.y - player.pos_y)
        if cand_d + 64.0 < cur_d:
            self._demo_targets[player_index] = candidate
            return candidate
        return current

    def _update_sim(self, dt: float, dt_ms: int) -> None:
        self._bonus_weapon_power_up_timer = max(0.0, self._bonus_weapon_power_up_timer - dt)
        self._update_creatures(dt, dt_ms)
        self._update_spawn_slots(dt)
        self._update_projectiles(dt)
        self._update_players(dt)
        self._update_fx(dt)
        self._update_camera(dt)

    def _nearest_player_index(self, x: float, y: float) -> int | None:
        best_idx = None
        best_dist = 0.0
        for idx, player in enumerate(self._players):
            d = _distance_sq(x, y, player.x, player.y)
            if best_idx is None or d < best_dist:
                best_idx = idx
                best_dist = d
        return best_idx

    def _nearest_creature_index(self, x: float, y: float) -> int | None:
        best_idx = None
        best_dist = 0.0
        for idx, creature in enumerate(self._creatures):
            if creature.hp <= 0.0:
                continue
            d = _distance_sq(x, y, creature.x, creature.y)
            if best_idx is None or d < best_dist:
                best_idx = idx
                best_dist = d
        return best_idx

    def _update_spawn_slots(self, dt: float) -> None:
        if not self._spawn_slots:
            return

        spawn_events: list[tuple[int, float, float]] = []
        slot_count = len(self._spawn_slots)
        for slot_idx in range(slot_count):
            slot = self._spawn_slots[slot_idx]
            owner_idx = slot.owner_creature
            if not (0 <= owner_idx < len(self._creatures)):
                continue
            owner = self._creatures[owner_idx]
            if owner.hp <= 0.0:
                continue
            child_template_id = tick_spawn_slot(slot, dt)
            if child_template_id is None:
                continue
            spawn_events.append((child_template_id, owner.x, owner.y))

        for child_template_id, x, y in spawn_events:
            self._spawn(child_template_id, x, y, heading=-100.0)

    def _update_creatures(self, dt: float, dt_ms: int) -> None:
        if not self._creatures or not self._players:
            return
        for creature in self._creatures:
            if creature.hp <= 0.0:
                continue
            type_id = creature.type_id
            if type_id is None:
                template = SPAWN_ID_TO_TEMPLATE.get(creature.spawn_id)
                type_id = template.type_id if template is not None else None

            move_speed = creature.move_speed
            if move_speed <= 0.0:
                move_speed = self._creature_speed(type_id) / 30.0

            creature_ai7_tick_link_timer(creature, dt_ms=dt_ms, rand=self._crand.rand)

            target_idx = self._nearest_player_index(creature.x, creature.y)
            creature.target_player = target_idx
            if target_idx is None:
                creature.vx = 0.0
                creature.vy = 0.0
                continue
            target = self._players[target_idx]
            ai = creature_ai_update_target(
                creature,
                player_x=target.x,
                player_y=target.y,
                creatures=self._creatures,
                dt=dt,
            )
            creature.move_scale = ai.move_scale
            if ai.self_damage is not None:
                creature.hp -= ai.self_damage
                if creature.hp <= 0.0:
                    continue

            if creature.ai_mode == 7:
                creature.vx = 0.0
                creature.vy = 0.0
                continue

            creature.heading = _angle_approach(
                creature.heading, creature.target_heading, move_speed * 0.33333334 * 4.0, dt
            )
            speed = move_speed * 30.0
            direction_x = math.cos(creature.heading - math.pi / 2.0)
            direction_y = math.sin(creature.heading - math.pi / 2.0)
            creature.vx = direction_x * dt * creature.move_scale * speed
            creature.vy = direction_y * dt * creature.move_scale * speed

            radius = max(0.0, creature.size)
            creature.x = _clamp(creature.x + creature.vx, radius, WORLD_SIZE - radius)
            creature.y = _clamp(creature.y + creature.vy, radius, WORLD_SIZE - radius)

    def _select_player_target(self, player: DemoPlayer) -> int | None:
        candidate = self._nearest_creature_index(player.x, player.y)
        current = player.target_creature
        if current is None:
            return candidate
        if not (0 <= current < len(self._creatures)):
            return candidate
        current_creature = self._creatures[current]
        if current_creature.hp <= 0.0:
            return candidate
        if candidate is None or candidate == current:
            return current
        cand_creature = self._creatures[candidate]
        if cand_creature.hp <= 0.0:
            return current
        cur_d = math.hypot(current_creature.x - player.x, current_creature.y - player.y)
        cand_d = math.hypot(cand_creature.x - player.x, cand_creature.y - player.y)
        if cand_d + 64.0 < cur_d:
            return candidate
        return current

    def _update_players(self, dt: float) -> None:
        if not self._players:
            return
        center_x = WORLD_SIZE * 0.5
        center_y = WORLD_SIZE * 0.5
        shot_cooldown_decay = dt * (1.5 if self._bonus_weapon_power_up_timer > 0.0 else 1.0)
        for player in self._players:
            player.shot_cooldown = max(0.0, player.shot_cooldown - shot_cooldown_decay)
            player.spread_heat = max(0.01, player.spread_heat - dt * 0.4)

            if player.reload_timer > 0.0:
                player.reload_timer = max(0.0, player.reload_timer - dt)
                if player.reload_timer <= 0.0:
                    weapon = self._weapon_entry(player.weapon_id)
                    clip_size = int(weapon.clip_size) if weapon is not None and weapon.clip_size is not None else 0
                    player.ammo = max(0, clip_size)
                    player.reload_timer = 0.0
                    player.reload_timer_max = 0.0

            player.target_creature = self._select_player_target(player)
            target = self._creatures[player.target_creature] if player.target_creature is not None else None
            if target is not None and target.hp > 0.0:
                dx = target.x - player.x
                dy = target.y - player.y
                nx, ny, _ = _normalize(dx, dy)
                player.aim_x, player.aim_y = nx, ny
            else:
                dx = center_x - player.x
                dy = center_y - player.y
                nx, ny, _ = _normalize(dx, dy)
                player.aim_x, player.aim_y = nx, ny

            move_x, move_y = 0.0, 0.0
            to_cx = center_x - player.x
            to_cy = center_y - player.y
            nx, ny, d = _normalize(to_cx, to_cy)
            if d > 120.0:
                move_x += nx
                move_y += ny

            if target is not None and target.hp > 0.0:
                rx = player.x - target.x
                ry = player.y - target.y
                rnx, rny, rd = _normalize(rx, ry)
                if 0.0 < rd < 160.0:
                    strength = (160.0 - rd) / 160.0
                    move_x += rnx * (1.5 * strength)
                    move_y += rny * (1.5 * strength)

            orbit_dir = -1.0 if (player.index % 2) else 1.0
            ox, oy, _ = _normalize(-(player.y - center_y), player.x - center_x)
            move_x += ox * 0.55 * orbit_dir
            move_y += oy * 0.55 * orbit_dir

            mnx, mny, _ = _normalize(move_x, move_y)
            speed = 150.0
            player.vx = mnx * speed
            player.vy = mny * speed
            player.x = _clamp(player.x + player.vx * dt, 0.0, WORLD_SIZE)
            player.y = _clamp(player.y + player.vy * dt, 0.0, WORLD_SIZE)

            self._player_fire(player, target)

    def _player_fire(self, player: DemoPlayer, target: DemoCreature | None) -> None:
        weapon = self._weapon_entry(player.weapon_id)
        if weapon is None:
            return

        if player.reload_timer > 0.0:
            return
        if player.shot_cooldown > 0.0:
            return
        if target is None or target.hp <= 0.0:
            return

        if player.ammo <= 0:
            reload_time = float(weapon.reload_time) if weapon.reload_time is not None else 0.0
            if self._bonus_weapon_power_up_timer > 0.0:
                reload_time *= 0.6
            player.reload_timer_max = max(0.0, reload_time)
            player.reload_timer = player.reload_timer_max
            play_sfx(self._state.audio, resolve_weapon_sfx_ref(weapon.reload_sound), rng=self._state.rng)
            return

        shot_cooldown = float(weapon.shot_cooldown) if weapon.shot_cooldown is not None else 0.0
        player.shot_cooldown = max(0.02, shot_cooldown)

        spread_inc = float(weapon.spread_heat_inc) if weapon.spread_heat_inc is not None else 0.0
        player.spread_heat = min(0.48, max(0.01, player.spread_heat + spread_inc))

        theta = math.atan2(player.aim_y, player.aim_x)
        if player.spread_heat > 0.0:
            theta += (self._crand_float01() * 2.0 - 1.0) * player.spread_heat
        angle = theta + math.pi / 2.0

        muzzle_x = player.x + player.aim_x * 16.0
        muzzle_y = player.y + player.aim_y * 16.0

        play_sfx(self._state.audio, resolve_weapon_sfx_ref(weapon.fire_sound), rng=self._state.rng)

        if player.weapon_id in {WeaponId.GAUSS_GUN, WeaponId.ION_MINIGUN}:
            meta = float(weapon.projectile_meta) if weapon.projectile_meta is not None else 0.0
            if meta <= 0.0:
                meta = 45.0
            type_id = projectile_type_id_from_weapon_id(player.weapon_id)
            if type_id is None:
                return
            self._projectile_pool.spawn(
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=angle,
                type_id=type_id,
                owner_id=-100,
                base_damage=meta,
            )
        elif player.weapon_id == WeaponId.ROCKET_LAUNCHER:
            self._secondary_projectile_pool.spawn(
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=angle,
                type_id=1,
            )
        elif player.weapon_id == WeaponId.PULSE_GUN:
            self._secondary_projectile_pool.spawn(
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=angle,
                type_id=4,
            )

        player.ammo = max(0, player.ammo - 1)
        if player.ammo <= 0:
            reload_time = float(weapon.reload_time) if weapon.reload_time is not None else 0.0
            if self._bonus_weapon_power_up_timer > 0.0:
                reload_time *= 0.6
            player.reload_timer_max = max(0.0, reload_time)
            player.reload_timer = player.reload_timer_max
            play_sfx(self._state.audio, resolve_weapon_sfx_ref(weapon.reload_sound), rng=self._state.rng)

    def _update_projectiles(self, dt: float) -> None:
        damage_scale_by_type: dict[int, float] = {}
        for type_id in (0x05, 0x0B, 0x15):
            weapon = weapon_entry_for_projectile_type_id(type_id)
            scale = float(weapon.damage_scale) if weapon is not None and weapon.damage_scale is not None else 0.0
            damage_scale_by_type[type_id] = scale if scale > 0.0 else 1.0

        hits = self._projectile_pool.update(
            dt,
            self._creatures,
            world_size=WORLD_SIZE,
            damage_scale_by_type=damage_scale_by_type,
            rng=self._crand.rand,
        )
        for type_id, origin_x, origin_y, hit_x, hit_y, *_ in hits:
            if type_id == 0x15:
                self._beams.append(
                    DemoBeam(
                        x0=origin_x,
                        y0=origin_y,
                        x1=hit_x,
                        y1=hit_y,
                        life=0.08,
                    )
                )
            if type_id == 0x0B:
                self._explosions.append(
                    DemoExplosion(
                        kind="rocket",
                        x=hit_x,
                        y=hit_y,
                        elapsed=0.0,
                        duration=0.35,
                        max_radius=90.0,
                        damage_per_tick=0.0,
                        tick_interval=1.0,
                    )
                )

        self._secondary_projectile_pool.update_pulse_gun(dt, self._creatures)
        self._creatures = [c for c in self._creatures if c.hp > 0.0]

    def _update_fx(self, dt: float) -> None:
        if self._beams:
            beams: list[DemoBeam] = []
            for beam in self._beams:
                beam.life -= dt
                if beam.life > 0.0:
                    beams.append(beam)
            self._beams = beams

        if not self._explosions:
            return
        survivors: list[DemoExplosion] = []
        for fx in self._explosions:
            fx.elapsed += dt
            if fx.damage_per_tick > 0.0 and fx.tick_interval > 0.0:
                fx.tick_accum += dt
                while fx.tick_accum >= fx.tick_interval:
                    fx.tick_accum -= fx.tick_interval
                    self._apply_explosion_damage(fx)
            if fx.elapsed < fx.duration:
                survivors.append(fx)
        self._explosions = survivors
        self._creatures = [c for c in self._creatures if c.hp > 0.0]

    def _apply_explosion_damage(self, fx: DemoExplosion) -> None:
        t = fx.elapsed / fx.duration if fx.duration > 0 else 1.0
        radius = fx.max_radius * _clamp(t, 0.0, 1.0)
        rsq = radius * radius
        for creature in self._creatures:
            if creature.hp <= 0.0:
                continue
            if _distance_sq(fx.x, fx.y, creature.x, creature.y) <= rsq:
                creature.hp -= fx.damage_per_tick

    def _update_camera(self, dt: float) -> None:
        if not self._players:
            return
        screen_w = float(self._state.config.screen_width)
        screen_h = float(self._state.config.screen_height)
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE

        if len(self._players) == 1:
            focus_x = self._players[0].x
            focus_y = self._players[0].y
        else:
            focus_x = sum(p.x for p in self._players) / len(self._players)
            focus_y = sum(p.y for p in self._players) / len(self._players)

        desired_x = (screen_w * 0.5) - focus_x
        desired_y = (screen_h * 0.5) - focus_y

        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        if desired_x > -1.0:
            desired_x = -1.0
        if desired_y > -1.0:
            desired_y = -1.0
        if desired_x < min_x:
            desired_x = min_x
        if desired_y < min_y:
            desired_y = min_y

        t = _clamp(dt * 6.0, 0.0, 1.0)
        self._camera_x = _lerp(self._camera_x, desired_x, t)
        self._camera_y = _lerp(self._camera_y, desired_y, t)
