from __future__ import annotations

import queue
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import msgspec

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
ReplayRenderPhase = Literal["video", "audio"]


class ReplayRenderError(ValueError):
    pass


_AUDIO_CAPTURE_SAMPLE_FORMAT = "f32le"
_AUDIO_CAPTURE_SAMPLE_RATE = 48_000
_AUDIO_CAPTURE_CHANNELS = 2
_AUDIO_INFERRED_SAMPLE_RATE_MIN = 8_000
_AUDIO_INFERRED_SAMPLE_RATE_MAX = 384_000
_AUDIO_OUTPUT_SAFETY_FILTER = "asoftclip=type=atan:threshold=1:output=1,volume=-1dB"


class ReplayRenderResult(msgspec.Struct, frozen=True):
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
    trace_rng: bool = False,
    ffmpeg_bin: Path | None = None,
    crf: int = 16,
    preset: X264Preset = "slow",
    pixel_format: str = "yuv420p",
    overwrite: bool = False,
    mute_audio: bool = True,
    progress: Callable[[ReplayRenderPhase, int, int, int], None] | None = None,
) -> ReplayRenderResult:
    from grim.config import ensure_crimson_cfg
    from grim.console import create_console
    from grim.raylib_api import rl
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
        trace_rng=bool(trace_rng),
    )

    runtime_base_dir = Path(base_dir)
    runtime_assets_dir = Path(assets_dir) if assets_dir is not None else runtime_base_dir
    runtime_base_dir.mkdir(parents=True, exist_ok=True)
    cfg = ensure_crimson_cfg(runtime_base_dir)
    capture_audio = not bool(mute_audio)
    # Always mute during the video pass: it is faster and prevents local playback.
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
    capture_width = 0
    capture_height = 0
    frame_bytes = 0
    total_ticks = int(len(replay.inputs))
    if max_ticks is not None:
        total_ticks = min(int(total_ticks), max(0, int(max_ticks)))
    config_flags = rl.ConfigFlags.FLAG_WINDOW_HIDDEN
    if int(config_flags) != 0:
        rl.set_config_flags(int(config_flags))

    with tempfile.TemporaryDirectory(prefix="crimson-replay-render-") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        video_out_path = out_path if not bool(capture_audio) else temp_dir / "video_only.mp4"
        audio_raw_path = temp_dir / "audio_mix.f32le"
        try:
            try:
                rl.init_window(int(render_width), int(render_height), f"Replay Render - {Path(replay_path).name}")
                window_open = True
            except RuntimeError as exc:
                raise ReplayRenderError(f"replay render could not initialize window: {exc}") from exc

            capture_width = int(rl.get_render_width())
            capture_height = int(rl.get_render_height())
            if int(capture_width) <= 0 or int(capture_height) <= 0:
                raise ReplayRenderError(
                    f"invalid framebuffer size from raylib: {capture_width}x{capture_height}; expected > 0",
                )
            frame_bytes = int(capture_width) * int(capture_height) * 4

            mode = ReplayPlaybackMode(
                ctx,
                replay_path=Path(replay_path),
                config=cfg,
                console=console,
                max_ticks=max_ticks,
                trace_rng=bool(trace_rng),
                show_replay_widget=False,
            )
            mode.open()

            ffmpeg_proc = _spawn_ffmpeg_raw_video_process(
                ffmpeg_path=ffmpeg_path,
                output_path=video_out_path,
                width=int(capture_width),
                height=int(capture_height),
                fps=int(fps),
                crf=int(crf),
                preset=str(preset),
                pixel_format=str(pixel_format),
                overwrite=True if bool(capture_audio) else bool(overwrite),
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
                    progress("video", int(frame_count), int(mode.tick_index), int(total_ticks))

            if int(frame_count) <= 0:
                raise ReplayRenderError("replay render produced no frames")

            if progress is not None:
                progress("video", int(frame_count), int(total_ticks), int(total_ticks))
            _finalize_ffmpeg_process(ffmpeg_proc)
            ffmpeg_proc = None
            if mode is not None:
                mode.close()
                mode = None

            if bool(capture_audio):
                replay_tick_rate = int(replay.header.tick_rate)
                if int(replay_tick_rate) <= 0:
                    raise ReplayRenderError(f"invalid replay tick_rate for audio pass: {replay_tick_rate}")
                captured_audio = _capture_replay_audio_track(
                    rl=rl,
                    ctx=ctx,
                    replay_path=Path(replay_path),
                    config=cfg,
                    console=console,
                    max_ticks=max_ticks,
                    trace_rng=bool(trace_rng),
                    output_path=audio_raw_path,
                    replay_tick_rate=int(replay_tick_rate),
                    progress=progress,
                    total_ticks=int(total_ticks),
                )
                _mux_raw_audio_with_video(
                    ffmpeg_path=ffmpeg_path,
                    video_path=video_out_path,
                    audio_path=audio_raw_path,
                    output_path=out_path,
                    overwrite=bool(overwrite),
                    audio_sample_rate=int(captured_audio.effective_sample_rate),
                    audio_channels=int(captured_audio.channels),
                    captured_audio_frames=int(captured_audio.captured_frames),
                    target_audio_frames=int(
                        round(
                            float(frame_count)
                            * float(captured_audio.effective_sample_rate)
                            / float(fps),
                        ),
                    ),
                )
                if progress is not None:
                    progress("audio", int(frame_count), int(total_ticks), int(total_ticks))
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
        width=int(capture_width),
        height=int(capture_height),
        run_result=baseline_result,
    )


class _MixedAudioCapture:
    def __init__(self, *, rl, output_path: Path, sample_rate: int, channels: int) -> None:
        if int(sample_rate) <= 0:
            raise ReplayRenderError(f"audio sample_rate must be > 0 (got {sample_rate})")
        if int(channels) <= 0:
            raise ReplayRenderError(f"audio channels must be > 0 (got {channels})")
        self._rl = rl
        self.output_path = Path(output_path)
        self.sample_rate = int(sample_rate)
        self.channels = int(channels)
        self._bytes_per_frame = int(self.channels) * 4
        self._queue: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self._captured_frames = 0
        self._callback_error: Exception | None = None
        self._attached = False
        self._closed = False
        self._file = self.output_path.open("wb")

        @self._rl.ffi.callback("void(void *, unsigned int)")
        def _callback(buffer_data, frames: int) -> None:
            self._on_mixed_audio(buffer_data=buffer_data, frames=int(frames))

        self._callback = _callback

    @property
    def captured_frames(self) -> int:
        return int(self._captured_frames)

    def _on_mixed_audio(self, *, buffer_data, frames: int) -> None:
        if self._closed or self._callback_error is not None:
            return
        frame_count = int(frames)
        if frame_count <= 0:
            return
        try:
            byte_count = int(frame_count) * int(self._bytes_per_frame)
            chunk = bytes(self._rl.ffi.buffer(buffer_data, int(byte_count)))
            self._queue.put(chunk)
            self._captured_frames += int(frame_count)
        except (BufferError, RuntimeError, TypeError, ValueError) as exc:  # pragma: no cover
            self._callback_error = exc

    def _raise_callback_error(self) -> None:
        exc = self._callback_error
        if exc is None:
            return
        raise ReplayRenderError(f"audio capture callback failed: {exc}") from exc

    def start(self) -> None:
        if self._attached:
            return
        self._rl.attach_audio_mixed_processor(self._callback)
        self._attached = True

    def flush_pending(self) -> None:
        self._raise_callback_error()
        while True:
            try:
                chunk = self._queue.get_nowait()
            except queue.Empty:
                break
            self._file.write(chunk)
        self._raise_callback_error()

    def stop(self) -> None:
        if self._closed:
            return
        if self._attached:
            self._rl.detach_audio_mixed_processor(self._callback)
            self._attached = False
        self.flush_pending()
        self._file.flush()

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.stop()
        finally:
            self._closed = True
            self._file.close()


class _CapturedAudioTrack(msgspec.Struct, frozen=True):
    sample_rate: int
    channels: int
    captured_frames: int
    captured_ticks: int
    effective_sample_rate: int


def _capture_replay_audio_track(
    *,
    rl,
    ctx,
    replay_path: Path,
    config,
    console,
    max_ticks: int | None,
    trace_rng: bool,
    output_path: Path,
    replay_tick_rate: int,
    progress: Callable[[ReplayRenderPhase, int, int, int], None] | None = None,
    total_ticks: int = 0,
) -> _CapturedAudioTrack:
    from ...modes.replay_playback_mode import ReplayPlaybackMode

    cfg = config
    cfg.set_bool_value("sound_disable", False)
    cfg.set_bool_value("music_disable", False)

    mode: ReplayPlaybackMode | None = None
    capture = _MixedAudioCapture(
        rl=rl,
        output_path=Path(output_path),
        sample_rate=int(_AUDIO_CAPTURE_SAMPLE_RATE),
        channels=int(_AUDIO_CAPTURE_CHANNELS),
    )
    prior_master_volume = 1.0
    try:
        mode = ReplayPlaybackMode(
            ctx,
            replay_path=Path(replay_path),
            config=cfg,
            console=console,
            max_ticks=max_ticks,
            trace_rng=bool(trace_rng),
            show_replay_widget=False,
        )
        mode.open()
        try:
            prior_master_volume = float(rl.get_master_volume())
        except RuntimeError:
            prior_master_volume = 1.0
        rl.set_master_volume(0.0)
        capture.start()

        tick_dt = 1.0 / float(replay_tick_rate)
        next_tick_deadline = time.perf_counter()
        while not bool(mode.finished):
            mode.update(float(tick_dt))
            if bool(mode.close_requested):
                raise ReplayRenderError("audio capture aborted: replay playback requested close")
            # Gameplay clears decal queues during draw(); audio-only rendering has no draw pass,
            # so clear here to avoid queue saturation changing deterministic outcomes.
            world = mode._world
            if world is not None:
                world.fx_queue.clear()
                world.fx_queue_rotated.clear()
            capture.flush_pending()
            if progress is not None and int(total_ticks) > 0:
                progress("audio", 0, int(mode.tick_index), int(total_ticks))
            next_tick_deadline += tick_dt
            sleep_s = float(next_tick_deadline) - float(time.perf_counter())
            if float(sleep_s) > 0.0:
                time.sleep(float(sleep_s))
        capture.stop()
        captured_ticks = int(mode.tick_index)
        effective_sample_rate = _infer_effective_capture_sample_rate(
            captured_frames=int(capture.captured_frames),
            captured_ticks=int(captured_ticks),
            replay_tick_rate=int(replay_tick_rate),
        )
        return _CapturedAudioTrack(
            sample_rate=int(capture.sample_rate),
            channels=int(capture.channels),
            captured_frames=int(capture.captured_frames),
            captured_ticks=int(captured_ticks),
            effective_sample_rate=int(effective_sample_rate),
        )
    finally:
        try:
            rl.set_master_volume(float(prior_master_volume))
        except RuntimeError:
            pass
        try:
            capture.close()
        except ReplayRenderError:
            pass
        if mode is not None:
            mode.close()


def _mux_raw_audio_with_video(
    *,
    ffmpeg_path: Path,
    video_path: Path,
    audio_path: Path,
    output_path: Path,
    overwrite: bool,
    audio_sample_rate: int,
    audio_channels: int,
    captured_audio_frames: int,
    target_audio_frames: int,
) -> None:
    if int(audio_sample_rate) <= 0:
        raise ReplayRenderError(f"invalid audio sample rate: {audio_sample_rate}")
    if int(audio_channels) <= 0:
        raise ReplayRenderError(f"invalid audio channel count: {audio_channels}")
    if int(captured_audio_frames) <= 0:
        raise ReplayRenderError(
            "audio capture produced no frames; if your system has no audio device, pass --mute-audio",
        )
    if int(target_audio_frames) <= 0:
        raise ReplayRenderError(
            "invalid target audio frame count for mux: "
            f"captured_frames={int(captured_audio_frames)} target_audio_frames={int(target_audio_frames)} "
            f"audio_sample_rate={int(audio_sample_rate)}",
        )
    audio_sync_filter = _build_audio_sync_filter(
        captured_frames=int(captured_audio_frames),
        target_frames=int(target_audio_frames),
    )
    # Mixed bus output can exceed full scale during dense overlaps; apply a
    # gentle soft clip with small headroom before AAC encode.
    audio_filter = f"{_AUDIO_OUTPUT_SAFETY_FILTER},{audio_sync_filter}"

    cmd = [
        str(ffmpeg_path),
        "-hide_banner",
        "-loglevel",
        "error",
        "-y" if bool(overwrite) else "-n",
        "-i",
        str(video_path),
        "-f",
        str(_AUDIO_CAPTURE_SAMPLE_FORMAT),
        "-ar",
        str(int(audio_sample_rate)),
        "-ac",
        str(int(audio_channels)),
        "-i",
        str(audio_path),
        "-map",
        "0:v:0",
        "-map",
        "1:a:0",
        "-af",
        audio_filter,
        "-c:v",
        "copy",
        "-c:a",
        "aac",
        "-b:a",
        "320k",
        "-shortest",
        "-movflags",
        "+faststart",
        str(output_path),
    ]
    proc = subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if int(proc.returncode) == 0:
        return
    stderr = proc.stderr.decode("utf-8", errors="replace").strip() if proc.stderr is not None else ""
    detail = stderr or "unknown ffmpeg error"
    raise ReplayRenderError(
        "ffmpeg audio mux failed "
        f"(exit {proc.returncode}): captured_frames={int(captured_audio_frames)} "
        f"target_audio_frames={int(target_audio_frames)} audio_sample_rate={int(audio_sample_rate)} "
        f"audio_channels={int(audio_channels)} output_safety_filter={_AUDIO_OUTPUT_SAFETY_FILTER!r} "
        f"sync_filter={audio_sync_filter!r} detail={detail}",
    )


def _build_audio_sync_filter(*, captured_frames: int, target_frames: int) -> str:
    captured = int(captured_frames)
    target = int(target_frames)
    if int(captured) <= 0:
        raise ReplayRenderError(f"audio sync filter requires captured_frames > 0 (got {captured})")
    if int(target) <= 0:
        raise ReplayRenderError(f"audio sync filter requires target_frames > 0 (got {target})")
    if int(captured) == int(target):
        return "asetpts=N/SR/TB"
    if int(captured) > int(target):
        return f"atrim=end_sample={int(target)},asetpts=N/SR/TB"
    pad = int(target) - int(captured)
    return f"apad=pad_len={int(pad)},atrim=end_sample={int(target)},asetpts=N/SR/TB"


def _infer_effective_capture_sample_rate(*, captured_frames: int, captured_ticks: int, replay_tick_rate: int) -> int:
    frames = int(captured_frames)
    ticks = int(captured_ticks)
    tick_rate = int(replay_tick_rate)
    fallback_rate = int(_AUDIO_CAPTURE_SAMPLE_RATE)
    if int(frames) <= 0:
        raise ReplayRenderError(
            "invalid audio capture for sample-rate inference: "
            f"captured_frames={int(frames)} captured_ticks={int(ticks)} replay_tick_rate={int(tick_rate)} "
            f"fallback_sample_rate={int(fallback_rate)}",
        )
    if int(ticks) <= 0 or int(tick_rate) <= 0:
        raise ReplayRenderError(
            "invalid replay timing for audio sample-rate inference: "
            f"captured_frames={int(frames)} captured_ticks={int(ticks)} replay_tick_rate={int(tick_rate)} "
            f"fallback_sample_rate={int(fallback_rate)}",
        )
    inferred = int(round(float(frames) * float(tick_rate) / float(ticks)))
    if _AUDIO_INFERRED_SAMPLE_RATE_MIN <= int(inferred) <= _AUDIO_INFERRED_SAMPLE_RATE_MAX:
        return int(inferred)
    raise ReplayRenderError(
        "inferred effective audio sample rate out of range: "
        f"captured_frames={int(frames)} captured_ticks={int(ticks)} replay_tick_rate={int(tick_rate)} "
        f"inferred_sample_rate={int(inferred)} allowed_range="
        f"{_AUDIO_INFERRED_SAMPLE_RATE_MIN}-{_AUDIO_INFERRED_SAMPLE_RATE_MAX} "
        f"fallback_sample_rate={int(fallback_rate)}",
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
    ]
    cmd.extend(
        [
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
        ],
    )
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
