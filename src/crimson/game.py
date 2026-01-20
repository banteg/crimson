from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import datetime as dt
import faulthandler
import random
import traceback

import pyray as rl

from .audio import AudioState, init_audio_state, play_music, update_audio, shutdown_audio
from .assets import LogoAssets, PaqTextureCache, load_logo_assets, load_paq_entries
from .config import CrimsonConfig, ensure_crimson_cfg
from .console import (
    ConsoleState,
    create_console,
    register_boot_commands,
    register_core_cvars,
)
from .entrypoint import DEFAULT_BASE_DIR
from .raylib_app import run_view
from .views.types import View


@dataclass(frozen=True, slots=True)
class GameConfig:
    base_dir: Path = DEFAULT_BASE_DIR
    assets_dir: Path | None = None
    width: int | None = None
    height: int | None = None
    fps: int = 60
    seed: int | None = None


@dataclass(slots=True)
class GameState:
    base_dir: Path
    assets_dir: Path
    rng: random.Random
    config: CrimsonConfig
    console: ConsoleState
    logos: LogoAssets | None
    texture_cache: PaqTextureCache | None
    audio: AudioState | None


TEXTURE_LOAD_STAGES: dict[int, tuple[tuple[str, str], ...]] = {
    0: (
        ("GRIM_Font2", "load/smallWhite.tga"),
        ("trooper", "game/trooper.jaz"),
        ("zombie", "game/zombie.jaz"),
        ("spider_sp1", "game/spider_sp1.jaz"),
        ("spider_sp2", "game/spider_sp2.jaz"),
        ("alien", "game/alien.jaz"),
        ("lizard", "game/lizard.jaz"),
    ),
    1: (
        ("arrow", "load/arrow.tga"),
        ("bullet_i", "load/bullet16.tga"),
        ("bulletTrail", "load/bulletTrail.tga"),
        ("bodyset", "game/bodyset.jaz"),
        ("projs", "game/projs.jaz"),
    ),
    2: (
        ("ui_iconAim", "ui/ui_iconAim.jaz"),
        ("ui_buttonSm", "ui/ui_button_64x32.jaz"),
        ("ui_buttonMd", "ui/ui_button_128x32.jaz"),
        ("ui_checkOn", "ui/ui_checkOn.jaz"),
        ("ui_checkOff", "ui/ui_checkOff.jaz"),
        ("ui_rectOff", "ui/ui_rectOff.jaz"),
        ("ui_rectOn", "ui/ui_rectOn.jaz"),
        ("bonuses", "game/bonuses.jaz"),
    ),
    3: (
        ("ui_indBullet", "ui/ui_indBullet.jaz"),
        ("ui_indRocket", "ui/ui_indRocket.jaz"),
        ("ui_indElectric", "ui/ui_indElectric.jaz"),
        ("ui_indFire", "ui/ui_indFire.jaz"),
        ("particles", "game/particles.jaz"),
    ),
    4: (
        ("ui_indLife", "ui/ui_indLife.jaz"),
        ("ui_indPanel", "ui/ui_indPanel.jaz"),
        ("ui_arrow", "ui/ui_arrow.jaz"),
        ("ui_cursor", "ui/ui_cursor.jaz"),
        ("ui_aim", "ui/ui_aim.jaz"),
    ),
    5: (
        ("ter_q1_base", "ter/ter_q1_base.jaz"),
        ("ter_q1_tex1", "ter/ter_q1_tex1.jaz"),
        ("ter_q2_base", "ter/ter_q2_base.jaz"),
        ("ter_q2_tex1", "ter/ter_q2_tex1.jaz"),
        ("ter_q3_base", "ter/ter_q3_base.jaz"),
        ("ter_q3_tex1", "ter/ter_q3_tex1.jaz"),
        ("ter_q4_base", "ter/ter_q4_base.jaz"),
        ("ter_q4_tex1", "ter/ter_q4_tex1.jaz"),
    ),
    6: (
        ("ui_textLevComp", "ui/ui_textLevComp.jaz"),
        ("ui_textQuest", "ui/ui_textQuest.jaz"),
        ("ui_num1", "ui/ui_num1.jaz"),
        ("ui_num2", "ui/ui_num2.jaz"),
        ("ui_num3", "ui/ui_num3.jaz"),
        ("ui_num4", "ui/ui_num4.jaz"),
        ("ui_num5", "ui/ui_num5.jaz"),
    ),
    7: (
        ("ui_wicons", "ui/ui_wicons.jaz"),
        ("iGameUI", "ui/ui_gameTop.jaz"),
        ("iHeart", "ui/ui_lifeHeart.jaz"),
        ("ui_clockTable", "ui/ui_clockTable.jaz"),
        ("ui_clockPointer", "ui/ui_clockPointer.jaz"),
    ),
    8: (
        ("game_muzzleFlash", "game/muzzleFlash.jaz"),
        ("ui_dropOn", "ui/ui_dropDownOn.jaz"),
        ("ui_dropOff", "ui/ui_dropDownOff.jaz"),
    ),
    9: (),
}

LOGO_SEQUENCE: tuple[tuple[str, str, float], ...] = (
    ("splash10tons", "load/splash10tons.jaz", 2.0),
    ("splashReflexive", "load/splashReflexive.jpg", 2.0),
)
LOADING_HOLD_SECONDS = 2.0

MENU_PREP_TEXTURES: tuple[tuple[str, str], ...] = (
    ("ui_signCrimson", "ui/ui_signCrimson.jaz"),
    ("ui_menuItem", "ui/ui_menuItem.jaz"),
    ("ui_menuPanel", "ui/ui_menuPanel.jaz"),
)


class BootView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._texture_stage = 0
        self._textures_done = False
        self._phase = "loading"
        self._phase_time = 0.0
        self._logo_index = 0
        self._menu_prepped = False

    def _load_texture_stage(self, stage: int) -> None:
        cache = self._state.texture_cache
        if cache is None:
            return
        stage_defs = TEXTURE_LOAD_STAGES.get(stage)
        if not stage_defs:
            return
        for name, rel_path in stage_defs:
            cache.get_or_load(name, rel_path)

    def _start_logo_sequence(self) -> None:
        cache = self._state.texture_cache
        if cache is None:
            return
        for name, rel_path, _duration in LOGO_SEQUENCE:
            cache.get_or_load(name, rel_path)
        loaded = sum(
            1
            for name, _rel, _duration in LOGO_SEQUENCE
            if cache.get(name) and cache.get(name).texture is not None
        )
        if LOGO_SEQUENCE:
            self._state.console.log.log(
                f"company logos loaded: {loaded}/{len(LOGO_SEQUENCE)}"
            )
            self._state.console.log.flush()
        self._phase = "logo_sequence"
        self._phase_time = 0.0
        self._logo_index = 0

    def _prepare_menu_assets(self) -> None:
        if self._menu_prepped:
            return
        cache = self._state.texture_cache
        if cache is None:
            return
        for name, rel_path in MENU_PREP_TEXTURES:
            cache.get_or_load(name, rel_path)
        loaded = sum(
            1
            for name, _rel in MENU_PREP_TEXTURES
            if cache.get(name) and cache.get(name).texture is not None
        )
        if MENU_PREP_TEXTURES:
            self._state.console.log.log(
                f"menu textures loaded: {loaded}/{len(MENU_PREP_TEXTURES)}"
            )
            self._state.console.log.flush()
        self._menu_prepped = True
        if self._state.audio is not None:
            play_music(self._state.audio, "crimson_theme")

    def open(self) -> None:
        if self._state.logos is None:
            entries = load_paq_entries(self._state.assets_dir)
            logos = load_logo_assets(self._state.assets_dir, entries=entries)
            self._state.console.log.log(
                f"logo assets: {logos.loaded_count()}/{len(logos.all())} loaded"
            )
            self._state.console.log.flush()
            self._state.logos = logos
            self._state.texture_cache = PaqTextureCache(entries=entries, textures={})
        if self._state.audio is None:
            self._state.audio = init_audio_state(
                self._state.config, self._state.assets_dir, self._state.console
            )

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio)
        if not self._textures_done:
            if self._texture_stage in TEXTURE_LOAD_STAGES:
                self._load_texture_stage(self._texture_stage)
                self._texture_stage += 1
                if self._texture_stage >= len(TEXTURE_LOAD_STAGES):
                    self._textures_done = True
                    self._phase_time = 0.0
                    if self._state.texture_cache is not None:
                        loaded = self._state.texture_cache.loaded_count()
                        total = len(self._state.texture_cache.textures)
                        self._state.console.log.log(
                            f"boot textures loaded: {loaded}/{total}"
                        )
                        self._state.console.log.flush()
            return

        if self._phase == "loading":
            self._phase_time += dt
            if self._phase_time < LOADING_HOLD_SECONDS:
                return
            self._start_logo_sequence()
            return
        if self._phase == "logo_sequence":
            self._phase_time += dt
            if not LOGO_SEQUENCE:
                return
            _name, _rel, duration = LOGO_SEQUENCE[self._logo_index]
            if self._phase_time >= duration:
                self._phase_time = 0.0
                if self._logo_index + 1 < len(LOGO_SEQUENCE):
                    self._logo_index += 1
                else:
                    self._phase = "menu_ready"
                    self._prepare_menu_assets()
        elif self._phase == "menu_ready":
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._phase == "loading":
            logos = self._state.logos
            if logos is not None:
                self._draw_splash(logos)
            return
        self._draw_company_logo()

    def close(self) -> None:
        if self._state.logos is not None:
            self._state.logos.unload()
        if self._state.texture_cache is not None:
            self._state.texture_cache.unload()
        if self._state.audio is not None:
            shutdown_audio(self._state.audio)

    def _draw_company_logo(self) -> None:
        if not LOGO_SEQUENCE:
            return
        cache = self._state.texture_cache
        if cache is None:
            return
        name, rel_path, _duration = LOGO_SEQUENCE[self._logo_index]
        asset = cache.get_or_load(name, rel_path)
        if asset.texture is None:
            return
        tex = asset.texture
        tex_w = float(tex.width)
        tex_h = float(tex.height)
        x = (rl.get_screen_width() - tex_w) * 0.5
        y = (rl.get_screen_height() - tex_h) * 0.5
        rl.draw_texture_v(tex, rl.Vector2(x, y), rl.WHITE)

    def _draw_splash(self, logos: LogoAssets) -> None:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())

        logo = logos.cl_logo.texture
        logo_h = float(logo.height) if logo is not None else 64.0
        band_height = logo_h * 2.0
        band_top = (screen_h - band_height) * 0.5 - 4.0
        band_bottom = band_top + band_height

        back = logos.backplasma.texture
        if back is not None:
            rl.draw_texture_pro(
                back,
                rl.Rectangle(0, 0, float(back.width), float(back.height)),
                rl.Rectangle(0, band_top, screen_w, band_height),
                rl.Vector2(0, 0),
                0.0,
                rl.Color(128, 128, 128, 255),
            )
        line_color = rl.Color(104, 122, 138, 255)
        rl.draw_rectangle(0, int(round(band_top)), int(screen_w), 1, line_color)
        rl.draw_rectangle(0, int(round(band_bottom)), int(screen_w), 1, line_color)

        if logo is not None:
            logo_w = float(logo.width)
            logo_h = float(logo.height)
            logo_x = (screen_w - logo_w) * 0.5
            logo_y = (screen_h - logo_h) * 0.5
            rl.draw_texture_v(logo, rl.Vector2(logo_x, logo_y), rl.WHITE)
            loading = logos.loading.texture
            if loading is not None:
                loading_w = float(loading.width)
                loading_h = float(loading.height)
                loading_x = logo_x + logo_w
                loading_y = logo_y + logo_h - loading_h
                rl.draw_texture_v(loading, rl.Vector2(loading_x, loading_y), rl.WHITE)

        esrb = logos.logo_esrb.texture
        if esrb is not None:
            esrb_w = float(esrb.width)
            esrb_h = float(esrb.height)
            esrb_x = screen_w - esrb_w
            esrb_y = screen_h - esrb_h
            rl.draw_texture_v(esrb, rl.Vector2(esrb_x, esrb_y), rl.WHITE)


def run_game(config: GameConfig) -> None:
    base_dir = config.base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    crash_path = base_dir / "crash.log"
    crash_file = crash_path.open("a", encoding="utf-8", buffering=1)
    faulthandler.enable(crash_file)
    crash_file.write(f"\n[{dt.datetime.now().isoformat()}] run_game start\n")
    cfg = ensure_crimson_cfg(base_dir)
    width = cfg.screen_width if config.width is None else config.width
    height = cfg.screen_height if config.height is None else config.height
    rng = random.Random(config.seed)
    console = create_console(base_dir)
    assets_dir = config.assets_dir if config.assets_dir is not None else base_dir
    try:
        register_boot_commands(console)
        register_core_cvars(console, width, height)
        console.log.log("crimson: boot start")
        console.log.log(
            f"config: {cfg.screen_width}x{cfg.screen_height} windowed={cfg.windowed_flag}"
        )
        console.log.log(f"commands: {len(console.commands)} registered")
        console.log.log(f"cvars: {len(console.cvars)} registered")
        console.exec_line("exec autoexec.txt")
        console.log.flush()
        state = GameState(
            base_dir=base_dir,
            assets_dir=assets_dir,
            rng=rng,
            config=cfg,
            console=console,
            logos=None,
            texture_cache=None,
            audio=None,
        )
        config_flags = 0
        if cfg.windowed_flag == 0:
            config_flags |= rl.ConfigFlags.FLAG_FULLSCREEN_MODE
        view: View = BootView(state)
        run_view(
            view,
            width=width,
            height=height,
            title="Crimsonland",
            fps=config.fps,
            config_flags=config_flags,
        )
    except Exception:
        crash_file.write("python exception:\n")
        crash_file.write(traceback.format_exc())
        crash_file.write("\n")
        crash_file.flush()
        raise
    finally:
        faulthandler.disable()
        crash_file.close()
