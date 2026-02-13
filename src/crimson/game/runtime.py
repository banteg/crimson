from __future__ import annotations

from pathlib import Path
import datetime as dt
import faulthandler
import random
import time
import traceback
import webbrowser

import pyray as rl

from grim import music
from grim.app import run_view
from grim.assets import PaqTextureCache, load_paq_entries_from_path
from grim.config import ensure_crimson_cfg
from grim.console import (
    CommandHandler,
    ConsoleState,
    create_console,
    register_boot_commands,
    register_core_cvars,
)
from grim.view import View

from ..assets_fetch import download_missing_paqs
from ..debug import set_debug_enabled
from ..demo_trial import (
    DEMO_QUEST_GRACE_TIME_MS,
    DEMO_TOTAL_PLAY_TIME_MS,
    demo_trial_overlay_info,
    format_demo_trial_time,
)
from ..frontend.assets import _ensure_texture_cache
from ..frontend.menu import ensure_menu_ground
from ..persistence.save_status import ensure_game_status
from ..quests.types import parse_level
from .loop_view import GameLoopView
from .types import GameConfig, GameState

CRIMSON_PAQ_NAME = "crimson.paq"
MUSIC_PAQ_NAME = "music.paq"
SFX_PAQ_NAME = "sfx.paq"
AUTOEXEC_NAME = "autoexec.txt"
REQUIRED_RUNTIME_PAQS: tuple[str, ...] = (CRIMSON_PAQ_NAME,)
OPTIONAL_AUDIO_PAQ_FALLBACKS: tuple[tuple[str, str], ...] = (
    (MUSIC_PAQ_NAME, "music"),
    (SFX_PAQ_NAME, "sfx"),
)


def _runtime_download_targets(assets_dir: Path) -> tuple[str, ...]:
    names: list[str] = [CRIMSON_PAQ_NAME]
    for paq_name, dir_name in OPTIONAL_AUDIO_PAQ_FALLBACKS:
        if (assets_dir / paq_name).is_file() or (assets_dir / dir_name).is_dir():
            continue
        names.append(paq_name)
    return tuple(names)


def _require_runtime_assets(assets_dir: Path) -> None:
    missing = [name for name in REQUIRED_RUNTIME_PAQS if not (assets_dir / name).is_file()]
    if missing:
        joined = ", ".join(missing)
        raise FileNotFoundError(f"assets: missing required archives: {joined}")
    missing_audio = [
        f"{paq_name} (or {dir_name}/)"
        for paq_name, dir_name in OPTIONAL_AUDIO_PAQ_FALLBACKS
        if not (assets_dir / paq_name).is_file() and not (assets_dir / dir_name).is_dir()
    ]
    if missing_audio:
        joined = ", ".join(missing_audio)
        raise FileNotFoundError(f"assets: missing audio archives or unpacked directories: {joined}")

def _parse_float_arg(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return 0.0


def _cvar_float(console: ConsoleState, name: str, default: float = 0.0) -> float:
    cvar = console.cvars.get(name)
    if cvar is None:
        return default
    return float(cvar.value_f)


def _resolve_resource_paq_path(state: GameState, raw: str) -> Path | None:
    candidate = Path(raw)
    if candidate.is_file():
        return candidate
    if not candidate.is_absolute():
        for base in (state.assets_dir, state.base_dir):
            path = base / candidate
            if path.is_file():
                return path
    return None


def _boot_command_handlers(state: GameState) -> dict[str, CommandHandler]:
    console = state.console

    def cmd_set_gamma_ramp(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("setGammaRamp <scalar > 0>")
            console.log.log("Command adjusts gamma ramp linearly by multiplying with given scalar")
            return
        value = _parse_float_arg(args[0])
        state.gamma_ramp = value
        console.log.log(f"Gamma ramp regenerated and multiplied with {value:.6f}")

    def cmd_snd_add_game_tune(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("snd_addGameTune <tuneName.ogg>")
            return
        audio = state.audio
        if audio is None:
            return
        rel_path = f"music/{args[0]}"
        result = music.load_music_track(audio.music, state.assets_dir, rel_path, console=console)
        if result is None:
            return
        track_key, _track_id = result
        music.queue_track(audio.music, track_key)

    def cmd_generate_terrain(_args: list[str]) -> None:
        ensure_menu_ground(state, regenerate=True)

    def cmd_tell_time_survived(_args: list[str]) -> None:
        seconds = int(max(0.0, time.monotonic() - state.session_start))
        console.log.log(f"Survived: {seconds} seconds.")

    def cmd_set_resource_paq(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("setresourcepaq <resourcepaq>")
            return
        raw = args[0]
        resolved = _resolve_resource_paq_path(state, raw)
        if resolved is None:
            console.log.log(f"File '{raw}' not found.")
            return
        entries = load_paq_entries_from_path(resolved)
        state.resource_paq = resolved
        if state.texture_cache is None:
            state.texture_cache = PaqTextureCache(entries=entries, textures={})
        else:
            state.texture_cache.entries = entries
        console.log.log(f"Set resource paq to '{raw}'")

    def cmd_load_texture(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("loadtexture <texturefileid>")
            return
        name = args[0]
        rel_path = name.replace("\\", "/")
        try:
            cache = _ensure_texture_cache(state)
        except FileNotFoundError:
            console.log.log(f"...loading texture '{name}' failed")
            return
        existing = cache.get(name)
        if existing is not None and existing.texture is not None:
            return
        try:
            asset = cache.get_or_load(name, rel_path)
        except FileNotFoundError:
            console.log.log(f"...loading texture '{name}' failed")
            return
        if asset.texture is None:
            console.log.log(f"...loading texture '{name}' failed")
            return
        if _cvar_float(console, "cv_silentloads", 0.0) == 0.0:
            console.log.log(f"...loading texture '{name}' ok")

    def cmd_open_url(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("openurl <url>")
            return
        url = args[0]
        ok = False
        try:
            ok = webbrowser.open(url)
        except Exception:
            ok = False
        if ok:
            console.log.log(f"Launching web browser ({url})..")
        else:
            console.log.log("Failed to launch web browser.")

    def cmd_snd_freq_adjustment(_args: list[str]) -> None:
        state.snd_freq_adjustment_enabled = not state.snd_freq_adjustment_enabled
        if state.snd_freq_adjustment_enabled:
            console.log.log("Sound frequency adjustment is now enabled.")
        else:
            console.log.log("Sound frequency adjustment is now disabled.")

    def cmd_demo_trial_set_playtime(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("demoTrialSetPlaytime <ms>")
            return
        try:
            value = int(float(args[0]))
        except ValueError:
            value = 0
        state.status.game_sequence_id = max(0, value)
        state.status.save_if_dirty()
        console.log.log(f"demo trial: playtime={state.status.game_sequence_id}ms (total {DEMO_TOTAL_PLAY_TIME_MS}ms)")

    def cmd_demo_trial_set_grace(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("demoTrialSetGrace <ms>")
            return
        try:
            value = int(float(args[0]))
        except ValueError:
            value = 0
        state.demo_trial_elapsed_ms = max(0, value)
        console.log.log(f"demo trial: quest grace={state.demo_trial_elapsed_ms}ms (total {DEMO_QUEST_GRACE_TIME_MS}ms)")

    def cmd_demo_trial_reset(_args: list[str]) -> None:
        state.status.game_sequence_id = 0
        state.status.save_if_dirty()
        state.demo_trial_elapsed_ms = 0
        console.log.log("demo trial: timers reset")

    def cmd_demo_trial_info(_args: list[str]) -> None:
        mode_id = state.config.game_mode
        quest_major = 0
        quest_minor = 0
        if mode_id == 3:
            level = state.pending_quest_level or ""
            if level:
                try:
                    quest_major, quest_minor = parse_level(level)
                except ValueError:
                    quest_major, quest_minor = 0, 0
        info = demo_trial_overlay_info(
            demo_build=bool(state.demo_enabled),
            game_mode_id=mode_id,
            global_playtime_ms=int(state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(state.demo_trial_elapsed_ms),
            quest_stage_major=int(quest_major),
            quest_stage_minor=int(quest_minor),
        )
        remaining = format_demo_trial_time(info.remaining_ms)
        console.log.log(
            "demo trial: "
            f"demo={int(state.demo_enabled)} "
            f"mode={mode_id} "
            f"quest={quest_major}.{quest_minor} "
            f"playtime={int(state.status.game_sequence_id)}ms "
            f"grace={int(state.demo_trial_elapsed_ms)}ms "
            f"visible={int(info.visible)} "
            f"kind={info.kind} "
            f"remaining={remaining}"
        )

    return {
        "setGammaRamp": cmd_set_gamma_ramp,
        "snd_addGameTune": cmd_snd_add_game_tune,
        "generateterrain": cmd_generate_terrain,
        "telltimesurvived": cmd_tell_time_survived,
        "setresourcepaq": cmd_set_resource_paq,
        "loadtexture": cmd_load_texture,
        "openurl": cmd_open_url,
        "sndfreqadjustment": cmd_snd_freq_adjustment,
        "demoTrialSetPlaytime": cmd_demo_trial_set_playtime,
        "demoTrialSetGrace": cmd_demo_trial_set_grace,
        "demoTrialReset": cmd_demo_trial_reset,
        "demoTrialInfo": cmd_demo_trial_info,
    }


def _resolve_assets_dir(config: GameConfig) -> Path:
    if config.assets_dir is not None:
        return config.assets_dir
    return config.base_dir


def run_game(config: GameConfig) -> None:
    if config.debug:
        set_debug_enabled(True)
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
    assets_dir = _resolve_assets_dir(config)
    console = create_console(base_dir, assets_dir=assets_dir)
    status = ensure_game_status(base_dir)
    state: GameState | None = None
    try:
        state = GameState(
            base_dir=base_dir,
            assets_dir=assets_dir,
            rng=rng,
            config=cfg,
            status=status,
            console=console,
            demo_enabled=bool(config.demo_enabled),
            preserve_bugs=bool(config.preserve_bugs),
            skip_intro=bool(config.no_intro),
            logos=None,
            texture_cache=None,
            audio=None,
            resource_paq=assets_dir / CRIMSON_PAQ_NAME,
            session_start=time.monotonic(),
        )
        register_boot_commands(console, _boot_command_handlers(state))
        register_core_cvars(console, width, height)
        console.log.log("crimson: boot start")
        console.log.log(f"config: {cfg.screen_width}x{cfg.screen_height} windowed={cfg.windowed_flag}")
        console.log.log(f"status: {status.path.name} loaded")
        console.log.log(f"assets: {assets_dir}")
        download_missing_paqs(assets_dir, console, names=_runtime_download_targets(assets_dir))
        _require_runtime_assets(assets_dir)
        console.log.log(f"assets: required archives ready ({', '.join(REQUIRED_RUNTIME_PAQS)})")
        console.log.log(f"commands: {len(console.commands)} registered")
        console.log.log(f"cvars: {len(console.cvars)} registered")
        console.exec_line("exec autoexec.txt")
        console.log.flush()
        config_flags = 0
        if cfg.windowed_flag == 0:
            config_flags |= rl.ConfigFlags.FLAG_FULLSCREEN_MODE
        view: View = GameLoopView(state)
        run_view(
            view,
            width=width,
            height=height,
            title="Crimsonland",
            fps=config.fps,
            config_flags=config_flags,
            exit_key=rl.KeyboardKey.KEY_NULL,
        )
        if state is not None:
            state.status.save_if_dirty()
    except Exception:
        crash_file.write("python exception:\n")
        crash_file.write(traceback.format_exc())
        crash_file.write("\n")
        crash_file.flush()
        raise
    finally:
        faulthandler.disable()
        crash_file.close()
