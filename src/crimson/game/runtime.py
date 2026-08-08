from __future__ import annotations

import datetime as dt
import faulthandler
import time
import webbrowser
from pathlib import Path

from grim import music
from grim.app import ViewRunHooks, run_view
from grim.config import ensure_crimson_cfg
from grim.console import (
    CommandHandler,
    ConsoleState,
    create_console,
    register_boot_commands,
    register_core_cvars,
)
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import View

from ..assets_fetch import download_missing_paqs
from ..debug import set_debug_enabled
from ..demo_trial import (
    DEMO_QUEST_GRACE_TIME_MS,
    DEMO_TOTAL_PLAY_TIME_MS,
    demo_trial_overlay_info,
    format_demo_trial_time,
)
from ..game_modes import GameMode
from ..net.debug_log import close_lan_debug_log, init_lan_debug_log, lan_debug_log
from ..persistence.save_status import ensure_game_status
from ..render.rtx.mode import cycle_rtx_render_mode, mode_from_rtx_flag, parse_rtx_render_mode
from .loop_view import GameLoopView
from .types import GameConfig, GameState, LockstepEndpoint

CRIMSON_PAQ_NAME = "crimson.paq"
MUSIC_PAQ_NAME = "music.paq"
SFX_PAQ_NAME = "sfx.paq"
AUTOEXEC_NAME = "autoexec.txt"
REQUIRED_RUNTIME_PAQS: tuple[str, ...] = (CRIMSON_PAQ_NAME, MUSIC_PAQ_NAME, SFX_PAQ_NAME)


def _runtime_download_targets(assets_dir: Path) -> tuple[str, ...]:
    return tuple(name for name in REQUIRED_RUNTIME_PAQS if not (assets_dir / name).is_file())


def _require_runtime_assets(assets_dir: Path) -> None:
    missing = [name for name in REQUIRED_RUNTIME_PAQS if not (assets_dir / name).is_file()]
    if missing:
        joined = ", ".join(missing)
        raise FileNotFoundError(f"assets: missing required archives: {joined}")

def _parse_float_arg(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return 0.0


def _apply_debug_console_defaults(console: ConsoleState, *, debug: bool) -> None:
    if not bool(debug):
        return
    console.register_cvar("cv_showFPS", "1")


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
        state.terrain_regenerate_requested = True

    def cmd_tell_time_survived(_args: list[str]) -> None:
        seconds = int(max(0.0, float(state.survival_elapsed_ms)) * 0.00100000005)
        console.log.log(f"Survived: {seconds} seconds.")

    def cmd_set_resource_paq(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("setresourcepaq <resourcepaq>")
            return
        console.log.log("setresourcepaq is not supported in the rewrite.")

    def cmd_load_texture(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("loadtexture <texturefileid>")
            return
        console.log.log("loadtexture is not supported in the rewrite.")

    def cmd_open_url(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("openurl <url>")
            return
        url = args[0]
        ok = False
        try:
            ok = webbrowser.open(url)
        except (OSError, webbrowser.Error):
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
        state.status.play_time_ms = max(0, value)
        state.status.save_if_dirty()
        console.log.log(f"demo trial: playtime={state.status.play_time_ms}ms (total {DEMO_TOTAL_PLAY_TIME_MS}ms)")

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
        state.status.play_time_ms = 0
        state.status.save_if_dirty()
        state.demo_trial_elapsed_ms = 0
        console.log.log("demo trial: timers reset")

    def cmd_demo_trial_info(_args: list[str]) -> None:
        mode_raw = state.config.gameplay.mode
        try:
            mode_id = GameMode(mode_raw)
        except ValueError:
            mode_id = GameMode.DEMO
        quest_level = None
        match mode_id:
            case GameMode.QUESTS:
                quest_level = state.pending_quest_level
            case _:
                pass
        info = demo_trial_overlay_info(
            demo_build=bool(state.demo_enabled),
            game_mode_id=mode_id,
            global_playtime_ms=int(state.status.play_time_ms),
            quest_grace_elapsed_ms=int(state.demo_trial_elapsed_ms),
            quest_level=quest_level,
        )
        remaining = format_demo_trial_time(info.remaining_ms)
        console.log.log(
            "demo trial: "
            f"demo={int(state.demo_enabled)} "
            f"mode={int(mode_id)} "
            f"quest={(quest_level.text if quest_level is not None else '0.0')} "
            f"playtime={int(state.status.play_time_ms)}ms "
            f"grace={int(state.demo_trial_elapsed_ms)}ms "
            f"visible={int(info.visible)} "
            f"kind={info.kind} "
            f"remaining={remaining}",
        )

    def cmd_render_mode(args: list[str]) -> None:
        if len(args) > 1:
            console.log.log("rendermode <classic|rtx>")
            return
        if not args:
            console.log.log(f"Render mode is '{state.rtx_mode.value}'.")
            return
        try:
            mode = parse_rtx_render_mode(args[0])
        except ValueError:
            console.log.log("rendermode <classic|rtx>")
            return
        state.rtx_mode = mode
        console.log.log(f"Render mode set to '{state.rtx_mode.value}'.")

    def cmd_toggle_rtx(args: list[str]) -> None:
        if args:
            console.log.log("togglertx")
            return
        state.rtx_mode = cycle_rtx_render_mode(state.rtx_mode)
        console.log.log(f"Render mode set to '{state.rtx_mode.value}'.")

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
        "rendermode": cmd_render_mode,
        "togglertx": cmd_toggle_rtx,
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
    crash_file.write(f"\n[{dt.datetime.now(tz=dt.UTC).astimezone().isoformat()}] run_game start\n")
    cfg = ensure_crimson_cfg(base_dir)
    width = cfg.display.width if config.width is None else config.width
    height = cfg.display.height if config.height is None else config.height
    rng = Crand(config.seed)
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
            demo_enabled=config.demo_enabled,
            preserve_bugs=config.preserve_bugs,
            skip_intro=config.no_intro,
            resources=None,
            audio=None,
            session_start=time.monotonic(),
            rtx_mode=mode_from_rtx_flag(bool(config.rtx)),
            pending_network_session=config.pending_network_session,
        )
        pending = config.pending_network_session
        if pending is not None:
            from ..net.lockstep_protocol import current_build_id

            endpoint = pending.config.endpoint
            if isinstance(endpoint, LockstepEndpoint):
                host = str(endpoint.host)
                port = int(endpoint.port)
            else:
                host = str(endpoint.relay_host)
                port = int(endpoint.relay_port)
            log_path = init_lan_debug_log(
                base_dir=base_dir,
                role=str(pending.role),
                mode=str(pending.config.mode),
                build_id=str(current_build_id()),
                host=host,
                port=int(port),
                player_count=pending.config.player_count,
                auto_start=pending.auto_start,
                debug_enabled=config.debug,
            )
            lan_debug_log(
                "run_game_session",
                width=int(width),
                height=int(height),
                fps=int(config.fps),
                preserve_bugs=config.preserve_bugs,
            )
            console.log.log(f"lan debug log: {log_path}")
            print(f"[lan-debug] role={pending.role} log={log_path}")
        register_boot_commands(console, _boot_command_handlers(state))
        register_core_cvars(console, width, height)
        _apply_debug_console_defaults(console, debug=config.debug)
        console.log.log("crimson: boot start")
        console.log.log(f"config: {cfg.display.width}x{cfg.display.height} windowed={cfg.display.windowed}")
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
        if not cfg.display.windowed:
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
            hooks=ViewRunHooks(view),
        )
        if state is not None:
            state.status.save_if_dirty()
    finally:
        close_lan_debug_log()
        faulthandler.disable()
        crash_file.close()
