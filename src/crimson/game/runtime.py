from __future__ import annotations

import datetime as dt
import faulthandler
import math
import time
import webbrowser
from pathlib import Path

from grim.app import RunViewHooks, run_view
from grim.audio import game_tune_command
from grim.config import CrimsonConfig
from grim.console import CommandHandler, ConsoleState, register_boot_commands
from grim.rand import Crand
from grim.raylib_api import rl

from ..debug import set_debug_enabled
from ..input_codes import GAMEPAD_SLOT_COUNT, gamepad_snapshot, input_code_name, player_gamepad_index
from ..persistence.save_status import ensure_game_status
from ..render.rtx.mode import cycle_rtx_render_mode, mode_from_rtx_flag, parse_rtx_render_mode
from ..runtime_boot import boot_runtime
from ..screens.quest_views.shared import QUEST_HARDCORE_UNLOCK_INDEX
from .loop_view import GameLoopView
from .types import GameConfig, GameState

CRIMSON_PAQ_NAME = "crimson.paq"
MUSIC_PAQ_NAME = "music.paq"
SFX_PAQ_NAME = "sfx.paq"
AUTOEXEC_NAME = "autoexec.txt"
REQUIRED_RUNTIME_PAQS: tuple[str, ...] = (CRIMSON_PAQ_NAME, MUSIC_PAQ_NAME, SFX_PAQ_NAME)


def _require_runtime_assets(assets_dir: Path) -> None:
    missing = [name for name in REQUIRED_RUNTIME_PAQS if not (assets_dir / name).is_file()]
    if missing:
        joined = ", ".join(missing)
        raise FileNotFoundError(f"assets: missing required archives: {joined}")


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
        try:
            value = float(args[0])
        except ValueError:
            value = 0.0
        if not math.isfinite(value) or value <= 0.0:
            console.log.log("setGammaRamp requires a finite scalar greater than zero.")
            return
        state.gamma_ramp = value
        console.log.log(f"Gamma ramp regenerated and multiplied with {value:.6f}")

    def cmd_generate_terrain(_args: list[str]) -> None:
        state.terrain_regenerate_requested = True

    def cmd_tell_time_survived(_args: list[str]) -> None:
        seconds = int(max(0.0, float(state.run_elapsed_ms)) * 0.00100000005)
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

    def cmd_gamepads(args: list[str]) -> None:
        if args:
            console.log.log("gamepads")
            console.log.log("Lists connected gamepads with live stick/button state and player bindings")
            return
        snapshots = [snapshot for pad in range(GAMEPAD_SLOT_COUNT) if (snapshot := gamepad_snapshot(pad)) is not None]
        if not snapshots:
            console.log.log("gamepads: none connected")
        for snapshot in snapshots:
            console.log.log(snapshot.summary())
        controls = state.config.controls
        for player_index in range(int(state.config.gameplay.player_count)):
            player = controls.player(player_index)
            console.log.log(
                f"player {player_index + 1} (pad {player_gamepad_index(player_index)}): "
                f"move={player.movement.name} "
                f"x={input_code_name(player.move_axis_codes[1])} y={input_code_name(player.move_axis_codes[0])} "
                f"aim={player.aim_scheme.name} "
                f"x={input_code_name(player.aim_axis_codes[1])} y={input_code_name(player.aim_axis_codes[0])} "
                f"fire={input_code_name(player.fire_code)}",
            )

    return {
        "setGammaRamp": cmd_set_gamma_ramp,
        "snd_addGameTune": game_tune_command(console, state.assets_dir, lambda: state.audio),
        "generateterrain": cmd_generate_terrain,
        "telltimesurvived": cmd_tell_time_survived,
        "setresourcepaq": cmd_set_resource_paq,
        "loadtexture": cmd_load_texture,
        "openurl": cmd_open_url,
        "sndfreqadjustment": cmd_snd_freq_adjustment,
        "rendermode": cmd_render_mode,
        "togglertx": cmd_toggle_rtx,
        "gamepads": cmd_gamepads,
    }


def _resolve_assets_dir(config: GameConfig) -> Path:
    if config.assets_dir is not None:
        return config.assets_dir
    return config.base_dir


def _save_windowed(cfg: CrimsonConfig, *, windowed: bool) -> None:
    cfg.display.windowed = windowed
    cfg.save()


def run_game(config: GameConfig) -> None:
    if config.debug:
        set_debug_enabled(True)
    base_dir = config.base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    crash_path = base_dir / "crash.log"
    crash_file = crash_path.open("a", encoding="utf-8", buffering=1)
    faulthandler.enable(crash_file)
    crash_file.write(f"\n[{dt.datetime.now(tz=dt.UTC).astimezone().isoformat()}] run_game start\n")
    assets_dir = _resolve_assets_dir(config)
    boot = boot_runtime(base_dir, assets_dir, width=config.width, height=config.height)
    cfg = boot.config
    console = boot.console
    # Display options stand in for the original launcher, which saved its choices to crimson.cfg.
    cfg.display.width = boot.width
    cfg.display.height = boot.height
    if config.windowed is not None:
        cfg.display.windowed = config.windowed
    if (config.width, config.height, config.windowed) != (None, None, None):
        cfg.save()
    rng = Crand(config.seed)
    status = ensure_game_status(base_dir)
    # Native `game_frame_update` clears hardcore every frame while fewer than 40 quests are unlocked. Unlocks only
    # grow and the quest menu refuses the checkbox below that, so clearing it once at boot is the same.
    if status.quest_unlock_index < QUEST_HARDCORE_UNLOCK_INDEX:
        cfg.gameplay.hardcore = False
    state: GameState | None = None
    try:
        state = GameState(
            base_dir=base_dir,
            assets_dir=assets_dir,
            rng=rng,
            config=cfg,
            status=status,
            console=console,
            preserve_bugs=config.preserve_bugs,
            replay_checkpoints=config.replay_checkpoints,
            skip_intro=config.no_intro,
            resources=None,
            audio=None,
            session_start=time.monotonic(),
            rtx_mode=mode_from_rtx_flag(bool(config.rtx)),
        )
        register_boot_commands(console, _boot_command_handlers(state))
        _apply_debug_console_defaults(console, debug=config.debug)
        console.log.log("crimson: boot start")
        console.log.log(f"config: {cfg.display.width}x{cfg.display.height} windowed={cfg.display.windowed}")
        console.log.log(f"status: {status.path.name} loaded")
        console.log.log(f"assets: {assets_dir}")
        _require_runtime_assets(assets_dir)
        console.log.log(f"assets: required archives ready ({', '.join(REQUIRED_RUNTIME_PAQS)})")
        console.log.log(f"commands: {len(console.commands)} registered")
        console.log.log(f"cvars: {len(console.cvars)} registered")
        console.exec_line("exec autoexec.txt")
        console.log.flush()
        window_state = 0
        if not cfg.display.windowed:
            # Borderless keeps the desktop video mode and HiDPI scaling; raylib 6
            # exclusive fullscreen on macOS renders into a quarter of the framebuffer.
            window_state |= rl.ConfigFlags.FLAG_BORDERLESS_WINDOWED_MODE
        view = GameLoopView(state)
        run_view(
            view,
            width=boot.width,
            height=boot.height,
            title="Crimsonland",
            fps=config.fps,
            window_state=window_state,
            exit_key=rl.KeyboardKey.KEY_NULL,
            hooks=RunViewHooks(
                should_close=view.should_close,
                consume_screenshot_request=view.consume_screenshot_request,
                fullscreen_changed=lambda fullscreen: _save_windowed(cfg, windowed=not fullscreen),
                focus_changed=view.focus_changed,
            ),
            # Native F12 saves into the game directory.
            screenshot_dir=base_dir,
        )
        if state is not None:
            state.status.save_if_dirty()
    finally:
        faulthandler.disable()
        crash_file.close()
