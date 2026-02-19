from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...replay import Replay
from .replay_runner import run_replay
from .setup import RunResult

X264Preset = Literal[
    "ultrafast",
    "superfast",
    "veryfast",
    "faster",
    "fast",
    "medium",
    "slow",
    "slower",
    "veryslow",
]


class ReplayRenderError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReplayRenderResult:
    output_path: Path
    frame_count: int
    fps: int
    width: int
    height: int
    run_result: RunResult


def run_replay_render_video(
    replay: Replay,
    *,
    replay_path: Path,
    output_path: Path,
    base_dir: Path,
    assets_dir: Path | None = None,
    width: int | None = None,
    height: int | None = None,
    fps: int = 60,
    max_ticks: int | None = None,
    strict_events: bool = True,
    trace_rng: bool = False,
    ffmpeg_bin: Path | None = None,
    crf: int = 16,
    preset: X264Preset = "slow",
    pixel_format: str = "yuv420p",
    overwrite: bool = False,
    mute_audio: bool = True,
    progress: Callable[[int, int, int], None] | None = None,
) -> ReplayRenderResult:
    import pyray as rl

    from grim.config import ensure_crimson_cfg
    from grim.console import create_console
    from grim.view import ViewContext

    from ...assets_fetch import download_missing_paqs
    from ...modes.replay_playback_mode import ReplayPlaybackMode

    _validate_args(fps=int(fps), crf=int(crf))

    ffmpeg_path = _resolve_ffmpeg_binary(ffmpeg_bin=ffmpeg_bin)
    out_path = Path(output_path)
    if out_path.exists() and not bool(overwrite):
        raise ReplayRenderError(f"output exists: {out_path} (pass --overwrite to replace)")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    baseline_result = run_replay(
        replay,
        max_ticks=max_ticks,
        strict_events=bool(strict_events),
        trace_rng=bool(trace_rng),
    )

    runtime_base_dir = Path(base_dir)
    runtime_assets_dir = Path(assets_dir) if assets_dir is not None else runtime_base_dir
    runtime_base_dir.mkdir(parents=True, exist_ok=True)
    cfg = ensure_crimson_cfg(runtime_base_dir)
    if bool(mute_audio):
        cfg.set_bool_value("sound_disable", True)
        cfg.set_bool_value("music_disable", True)

    render_width = int(width) if width is not None else cfg.screen_width
    render_height = int(height) if height is not None else cfg.screen_height
    if int(render_width) <= 0 or int(render_height) <= 0:
        raise ReplayRenderError(
            f"invalid render resolution: {render_width}x{render_height}; width/height must be > 0",
        )

    console = create_console(runtime_base_dir, assets_dir=runtime_assets_dir)
    download_missing_paqs(runtime_assets_dir, console)
    ctx = ViewContext(assets_dir=runtime_assets_dir, preserve_bugs=False)

    frame_count = 0
    mode: ReplayPlaybackMode | None = None
    window_open = False
    ffmpeg_proc: subprocess.Popen[bytes] | None = None
    frame_bytes = int(render_width) * int(render_height) * 4
    total_ticks = int(len(replay.inputs))
    if max_ticks is not None:
        total_ticks = min(int(total_ticks), max(0, int(max_ticks)))
    config_flags = int(getattr(rl, "FLAG_WINDOW_HIDDEN", 0))
    if int(config_flags) != 0:
        rl.set_config_flags(int(config_flags))

    try:
        try:
            rl.init_window(int(render_width), int(render_height), f"Replay Render - {Path(replay_path).name}")
            window_open = True
        except RuntimeError as exc:
            raise ReplayRenderError(f"replay render could not initialize window: {exc}") from exc

        mode = ReplayPlaybackMode(
            ctx,
            replay_path=Path(replay_path),
            config=cfg,
            console=console,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
        )
        mode.open()
        ffmpeg_proc = _spawn_ffmpeg_raw_video_process(
            ffmpeg_path=ffmpeg_path,
            output_path=out_path,
            width=int(render_width),
            height=int(render_height),
            fps=int(fps),
            crf=int(crf),
            preset=str(preset),
            pixel_format=str(pixel_format),
            overwrite=bool(overwrite),
        )
        frame_dt = 1.0 / float(fps)
        while not bool(mode.finished):
            mode.update(float(frame_dt))
            rl.begin_drawing()
            mode.draw()
            rl.end_drawing()
            if bool(mode.close_requested):
                raise ReplayRenderError("replay render aborted: replay playback requested close")
            image = rl.load_image_from_screen()
            try:
                colors = rl.load_image_colors(image)
                try:
                    if ffmpeg_proc.stdin is None:
                        raise ReplayRenderError("ffmpeg stdin pipe was not available")
                    ffmpeg_proc.stdin.write(rl.ffi.buffer(colors, int(frame_bytes)))
                finally:
                    rl.unload_image_colors(colors)
            finally:
                rl.unload_image(image)
            frame_count += 1
            if progress is not None:
                progress(int(frame_count), int(mode.tick_index), int(total_ticks))

        if int(frame_count) <= 0:
            raise ReplayRenderError("replay render produced no frames")

        if progress is not None:
            progress(int(frame_count), int(total_ticks), int(total_ticks))
        _finalize_ffmpeg_process(ffmpeg_proc)
    except ReplayRenderError:
        _abort_ffmpeg_process(ffmpeg_proc)
        raise
    except BrokenPipeError as exc:
        _abort_ffmpeg_process(ffmpeg_proc)
        raise ReplayRenderError(f"ffmpeg stdin closed early: {exc}") from exc
    except OSError as exc:
        _abort_ffmpeg_process(ffmpeg_proc)
        raise ReplayRenderError(f"ffmpeg streaming failed: {exc}") from exc
    finally:
        if mode is not None:
            mode.close()
        if bool(window_open):
            rl.close_window()

    return ReplayRenderResult(
        output_path=Path(out_path),
        frame_count=int(frame_count),
        fps=int(fps),
        width=int(render_width),
        height=int(render_height),
        run_result=baseline_result,
    )


def _validate_args(*, fps: int, crf: int) -> None:
    if int(fps) <= 0:
        raise ReplayRenderError("fps must be > 0")
    if int(crf) < 0 or int(crf) > 51:
        raise ReplayRenderError("crf must be between 0 and 51")


def _resolve_ffmpeg_binary(*, ffmpeg_bin: Path | None) -> Path:
    if ffmpeg_bin is not None:
        ffmpeg_path = Path(ffmpeg_bin)
        if not ffmpeg_path.exists() or not ffmpeg_path.is_file():
            raise ReplayRenderError(f"ffmpeg binary not found: {ffmpeg_path}")
        return ffmpeg_path

    resolved = shutil.which("ffmpeg")
    if resolved is None:
        raise ReplayRenderError("ffmpeg binary not found in PATH; install ffmpeg or pass --ffmpeg-bin")
    return Path(resolved)


def _spawn_ffmpeg_raw_video_process(
    *,
    ffmpeg_path: Path,
    output_path: Path,
    width: int,
    height: int,
    fps: int,
    crf: int,
    preset: str,
    pixel_format: str,
    overwrite: bool,
) -> subprocess.Popen[bytes]:
    cmd = [
        str(ffmpeg_path),
        "-hide_banner",
        "-loglevel",
        "error",
        "-y" if bool(overwrite) else "-n",
        "-f",
        "rawvideo",
        "-pixel_format",
        "rgba",
        "-video_size",
        f"{int(width)}x{int(height)}",
        "-framerate",
        str(int(fps)),
        "-i",
        "-",
        "-c:v",
        "libx264",
        "-preset",
        str(preset),
        "-crf",
        str(int(crf)),
        "-pix_fmt",
        str(pixel_format),
        "-movflags",
        "+faststart",
        str(output_path),
    ]
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def _finalize_ffmpeg_process(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        raise ReplayRenderError("ffmpeg process was not initialized")
    if proc.stdin is not None and not proc.stdin.closed:
        proc.stdin.close()
    return_code = proc.wait()
    if int(return_code) == 0:
        return
    stderr = (proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr is not None else "").strip()
    detail = stderr or "unknown ffmpeg error"
    raise ReplayRenderError(f"ffmpeg encode failed (exit {return_code}): {detail}")


def _abort_ffmpeg_process(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        return
    if proc.stdin is not None and not proc.stdin.closed:
        try:
            proc.stdin.close()
        except OSError:
            pass
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2.0)
