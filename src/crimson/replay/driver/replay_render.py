from __future__ import annotations

import queue
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Literal

import msgspec

from ...render.pipeline import RenderPipeline
from ...render.sink import VideoSink, VideoTransport
from ...replay import Replay
from .playback_driver import build_verify_playback_driver
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


class ReplayRenderProgress(msgspec.Struct):
    def update(
        self,
        *,
        phase: ReplayRenderPhase,
        frame_count: int,
        tick_index: int,
        total_ticks: int,
    ) -> None:
        _ = phase, frame_count, tick_index, total_ticks

    def close(self) -> None:
        return None


class _FfmpegVideoTransport(VideoTransport):
    def __init__(
        self,
        *,
        rl,
        ffmpeg_path: Path,
        output_path: Path,
        width: int,
        height: int,
        fps: int,
        crf: int,
        preset: str,
        pixel_format: str,
        overwrite: bool,
    ) -> None:
        self._rl = rl
        self._ffmpeg_path = Path(ffmpeg_path)
        self._output_path = Path(output_path)
        self._width = max(0, width)
        self._height = max(0, height)
        self._fps = max(1, fps)
        self._crf = crf
        self._preset = preset
        self._pixel_format = pixel_format
        self._overwrite = overwrite
        self._proc: subprocess.Popen[bytes] | None = None
        self._frame_bytes = self._width * self._height * 4
        self._flushed = False

    def open(self) -> None:
        self._proc = _spawn_ffmpeg_raw_video_process(
            ffmpeg_path=self._ffmpeg_path,
            output_path=self._output_path,
            width=self._width,
            height=self._height,
            fps=self._fps,
            crf=self._crf,
            preset=self._preset,
            pixel_format=self._pixel_format,
            overwrite=self._overwrite,
        )
        self._flushed = False

    def present_frame(self) -> None:
        proc = self._proc
        if proc is None:
            raise ReplayRenderError("ffmpeg process was not initialized")
        image = self._rl.load_image_from_screen()
        try:
            colors = self._rl.load_image_colors(image)
            try:
                if proc.stdin is None:
                    raise ReplayRenderError("ffmpeg stdin pipe was not available")
                proc.stdin.write(self._rl.ffi.buffer(colors, self._frame_bytes))
            finally:
                self._rl.unload_image_colors(colors)
        finally:
            self._rl.unload_image(image)

    def flush(self) -> None:
        if self._flushed:
            return
        _finalize_ffmpeg_process(self._proc)
        self._proc = None
        self._flushed = True

    def close(self) -> None:
        _abort_ffmpeg_process(self._proc)
        self._proc = None


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
    progress: ReplayRenderProgress | None = None,
) -> ReplayRenderResult:
    from grim.assets import load_runtime_resources, unload_runtime_resources
    from grim.config import ensure_crimson_cfg
    from grim.console import create_console
    from grim.raylib_api import rl
    from grim.view import ViewContext

    from ...assets_fetch import download_missing_paqs
    from ...modes.replay_playback_mode import ReplayPlaybackMode

    _validate_args(fps=fps, crf=crf)

    ffmpeg_path = _resolve_ffmpeg_binary(ffmpeg_bin=ffmpeg_bin)
    out_path = Path(output_path)
    if out_path.exists() and not overwrite:
        raise ReplayRenderError(f"output exists: {out_path} (pass --overwrite to replace)")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    baseline_result = build_verify_playback_driver(
        replay,
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
    ).run()

    runtime_base_dir = Path(base_dir)
    runtime_assets_dir = Path(assets_dir) if assets_dir is not None else runtime_base_dir
    runtime_base_dir.mkdir(parents=True, exist_ok=True)
    cfg = ensure_crimson_cfg(runtime_base_dir)
    capture_audio = not mute_audio
    # Always mute during the video pass: it is faster and prevents local playback.
    cfg.audio.sound_disabled = True
    cfg.audio.music_disabled = True

    render_width = width if width is not None else cfg.display.width
    render_height = height if height is not None else cfg.display.height
    if render_width <= 0 or render_height <= 0:
        raise ReplayRenderError(
            f"invalid render resolution: {render_width}x{render_height}; width/height must be > 0",
        )

    console = create_console(runtime_base_dir, assets_dir=runtime_assets_dir)
    download_missing_paqs(runtime_assets_dir, console)
    ctx = ViewContext(assets_dir=runtime_assets_dir, preserve_bugs=False)

    frame_count = 0
    mode: ReplayPlaybackMode | None = None
    window_open = False
    render_pipeline: RenderPipeline | None = None
    capture_width = 0
    capture_height = 0
    total_ticks = len(replay.ticks)
    if max_ticks is not None:
        total_ticks = min(total_ticks, max(0, max_ticks))
    config_flags = rl.ConfigFlags.FLAG_WINDOW_HIDDEN
    if config_flags != 0:
        rl.set_config_flags(config_flags)

    with tempfile.TemporaryDirectory(prefix="crimson-replay-render-") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        video_out_path = out_path if not capture_audio else temp_dir / "video_only.mp4"
        audio_raw_path = temp_dir / "audio_mix.f32le"
        resources = None
        try:
            try:
                rl.init_window(render_width, render_height, f"Replay Render - {Path(replay_path).name}")
                window_open = True
            except RuntimeError as exc:
                raise ReplayRenderError(f"replay render could not initialize window: {exc}") from exc
            resources = load_runtime_resources(runtime_assets_dir)

            capture_width = rl.get_render_width()
            capture_height = rl.get_render_height()
            if capture_width <= 0 or capture_height <= 0:
                raise ReplayRenderError(
                    f"invalid framebuffer size from raylib: {capture_width}x{capture_height}; expected > 0",
                )

            mode = ReplayPlaybackMode(
                ctx,
                replay_path=Path(replay_path),
                config=cfg,
                console=console,
                max_ticks=max_ticks,
                trace_rng=trace_rng,
                show_replay_widget=False,
            )
            mode.open()
            video_transport = _FfmpegVideoTransport(
                rl=rl,
                ffmpeg_path=ffmpeg_path,
                output_path=video_out_path,
                width=capture_width,
                height=capture_height,
                fps=fps,
                crf=crf,
                preset=preset,
                pixel_format=pixel_format,
                overwrite=True if capture_audio else overwrite,
            )
            render_pipeline = RenderPipeline(
                sink=VideoSink(
                    output_path=video_out_path,
                    transport=video_transport,
                ),
                begin_end_drawing=True,
                begin_draw=rl.begin_drawing,
                end_draw=rl.end_drawing,
            )
            render_pipeline.open(width=capture_width, height=capture_height)
            assert render_pipeline is not None
            frame_dt = 1.0 / fps
            while not mode.finished:
                mode.update(frame_dt)
                render_pipeline.draw(
                    draw_frame=mode.draw,
                    width=capture_width,
                    height=capture_height,
                )
                if mode.close_requested:
                    raise ReplayRenderError("replay render aborted: replay playback requested close")
                render_pipeline.present()
                frame_count += 1
                if progress is not None:
                    progress.update(
                        phase="video",
                        frame_count=frame_count,
                        tick_index=mode.tick_index,
                        total_ticks=total_ticks,
                    )

            if frame_count <= 0:
                raise ReplayRenderError("replay render produced no frames")

            if progress is not None:
                progress.update(
                    phase="video",
                    frame_count=frame_count,
                    tick_index=total_ticks,
                    total_ticks=total_ticks,
                )
            render_pipeline.flush()
            render_pipeline.close()
            render_pipeline = None
            if mode is not None:
                mode.close()
                mode = None

            if capture_audio:
                replay_tick_rate = replay.header.tick_rate
                if replay_tick_rate <= 0:
                    raise ReplayRenderError(f"invalid replay tick_rate for audio pass: {replay_tick_rate}")
                captured_audio = _capture_replay_audio_track(
                    rl=rl,
                    ctx=ctx,
                    replay_path=Path(replay_path),
                    config=cfg,
                    console=console,
                    max_ticks=max_ticks,
                    trace_rng=trace_rng,
                    output_path=audio_raw_path,
                    replay_tick_rate=replay_tick_rate,
                    progress=progress,
                    total_ticks=total_ticks,
                )
                _mux_raw_audio_with_video(
                    ffmpeg_path=ffmpeg_path,
                    video_path=video_out_path,
                    audio_path=audio_raw_path,
                    output_path=out_path,
                    overwrite=overwrite,
                    audio_sample_rate=captured_audio.effective_sample_rate,
                    audio_channels=captured_audio.channels,
                    captured_audio_frames=captured_audio.captured_frames,
                    target_audio_frames=round(frame_count * captured_audio.effective_sample_rate / fps),
                )
                if progress is not None:
                    progress.update(
                        phase="audio",
                        frame_count=frame_count,
                        tick_index=total_ticks,
                        total_ticks=total_ticks,
                    )
        except ReplayRenderError:
            if render_pipeline is not None:
                render_pipeline.close()
                render_pipeline = None
            raise
        except BrokenPipeError as exc:
            if render_pipeline is not None:
                render_pipeline.close()
                render_pipeline = None
            raise ReplayRenderError(f"ffmpeg stdin closed early: {exc}") from exc
        except OSError as exc:
            if render_pipeline is not None:
                render_pipeline.close()
                render_pipeline = None
            raise ReplayRenderError(f"ffmpeg streaming failed: {exc}") from exc
        finally:
            if mode is not None:
                mode.close()
            if render_pipeline is not None:
                render_pipeline.close()
            unload_runtime_resources(resources)
            if window_open:
                rl.close_window()

    return ReplayRenderResult(
        output_path=out_path,
        frame_count=frame_count,
        fps=fps,
        width=capture_width,
        height=capture_height,
        run_result=baseline_result,
    )


class _MixedAudioCapture:
    def __init__(self, *, rl, output_path: Path, sample_rate: int, channels: int) -> None:
        if sample_rate <= 0:
            raise ReplayRenderError(f"audio sample_rate must be > 0 (got {sample_rate})")
        if channels <= 0:
            raise ReplayRenderError(f"audio channels must be > 0 (got {channels})")
        self._rl = rl
        self.output_path = Path(output_path)
        self.sample_rate = sample_rate
        self.channels = channels
        self._bytes_per_frame = self.channels * 4
        self._queue: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self._captured_frames = 0
        self._callback_error: Exception | None = None
        self._attached = False
        self._closed = False
        self._file = self.output_path.open("wb")

        @self._rl.ffi.callback("void(void *, unsigned int)")
        def _callback(buffer_data, frames: int) -> None:
            self._on_mixed_audio(buffer_data=buffer_data, frames=frames)

        self._callback = _callback

    @property
    def captured_frames(self) -> int:
        return self._captured_frames

    def _on_mixed_audio(self, *, buffer_data, frames: int) -> None:
        if self._closed or self._callback_error is not None:
            return
        frame_count = frames
        if frame_count <= 0:
            return
        try:
            byte_count = frame_count * self._bytes_per_frame
            chunk = bytes(self._rl.ffi.buffer(buffer_data, byte_count))
            self._queue.put(chunk)
            self._captured_frames += frame_count
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
    progress: ReplayRenderProgress | None = None,
    total_ticks: int = 0,
) -> _CapturedAudioTrack:
    from ...modes.replay_playback_mode import ReplayPlaybackMode

    cfg = config
    cfg.audio.sound_disabled = False
    cfg.audio.music_disabled = False

    mode: ReplayPlaybackMode | None = None
    capture = _MixedAudioCapture(
        rl=rl,
        output_path=Path(output_path),
        sample_rate=_AUDIO_CAPTURE_SAMPLE_RATE,
        channels=_AUDIO_CAPTURE_CHANNELS,
    )
    prior_master_volume = 1.0
    try:
        mode = ReplayPlaybackMode(
            ctx,
            replay_path=Path(replay_path),
            config=cfg,
            console=console,
            max_ticks=max_ticks,
            trace_rng=trace_rng,
            show_replay_widget=False,
        )
        mode.open()
        try:
            prior_master_volume = rl.get_master_volume()
        except RuntimeError:
            prior_master_volume = 1.0
        rl.set_master_volume(0.0)
        capture.start()

        tick_dt = 1.0 / replay_tick_rate
        next_tick_deadline = time.perf_counter()
        while not mode.finished:
            mode.update(tick_dt)
            if mode.close_requested:
                raise ReplayRenderError("audio capture aborted: replay playback requested close")
            capture.flush_pending()
            if progress is not None and total_ticks > 0:
                progress.update(
                    phase="audio",
                    frame_count=0,
                    tick_index=mode.tick_index,
                    total_ticks=total_ticks,
                )
            next_tick_deadline += tick_dt
            sleep_s = next_tick_deadline - time.perf_counter()
            if sleep_s > 0.0:
                time.sleep(sleep_s)
        capture.stop()
        captured_ticks = mode.tick_index
        effective_sample_rate = _infer_effective_capture_sample_rate(
            captured_frames=capture.captured_frames,
            captured_ticks=captured_ticks,
            replay_tick_rate=replay_tick_rate,
        )
        return _CapturedAudioTrack(
            sample_rate=capture.sample_rate,
            channels=capture.channels,
            captured_frames=capture.captured_frames,
            captured_ticks=captured_ticks,
            effective_sample_rate=effective_sample_rate,
        )
    finally:
        try:
            rl.set_master_volume(prior_master_volume)
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
    if audio_sample_rate <= 0:
        raise ReplayRenderError(f"invalid audio sample rate: {audio_sample_rate}")
    if audio_channels <= 0:
        raise ReplayRenderError(f"invalid audio channel count: {audio_channels}")
    if captured_audio_frames <= 0:
        raise ReplayRenderError(
            "audio capture produced no frames; if your system has no audio device, pass --mute-audio",
        )
    if target_audio_frames <= 0:
        raise ReplayRenderError(
            "invalid target audio frame count for mux: "
            f"captured_frames={captured_audio_frames} target_audio_frames={target_audio_frames} "
            f"audio_sample_rate={audio_sample_rate}",
        )
    audio_sync_filter = _build_audio_sync_filter(
        captured_frames=captured_audio_frames,
        target_frames=target_audio_frames,
    )
    # Mixed bus output can exceed full scale during dense overlaps; apply a
    # gentle soft clip with small headroom before AAC encode.
    audio_filter = f"{_AUDIO_OUTPUT_SAFETY_FILTER},{audio_sync_filter}"

    cmd = [
        str(ffmpeg_path),
        "-hide_banner",
        "-loglevel",
        "error",
        "-y" if overwrite else "-n",
        "-i",
        str(video_path),
        "-f",
        str(_AUDIO_CAPTURE_SAMPLE_FORMAT),
        "-ar",
        str(audio_sample_rate),
        "-ac",
        str(audio_channels),
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
    if proc.returncode == 0:
        return
    stderr = proc.stderr.decode("utf-8", errors="replace").strip() if proc.stderr is not None else ""
    detail = stderr or "unknown ffmpeg error"
    raise ReplayRenderError(
        "ffmpeg audio mux failed "
        f"(exit {proc.returncode}): captured_frames={captured_audio_frames} "
        f"target_audio_frames={target_audio_frames} audio_sample_rate={audio_sample_rate} "
        f"audio_channels={audio_channels} output_safety_filter={_AUDIO_OUTPUT_SAFETY_FILTER!r} "
        f"sync_filter={audio_sync_filter!r} detail={detail}",
    )


def _build_audio_sync_filter(*, captured_frames: int, target_frames: int) -> str:
    captured = captured_frames
    target = target_frames
    if captured <= 0:
        raise ReplayRenderError(f"audio sync filter requires captured_frames > 0 (got {captured})")
    if target <= 0:
        raise ReplayRenderError(f"audio sync filter requires target_frames > 0 (got {target})")
    if captured == target:
        return "asetpts=N/SR/TB"
    if captured > target:
        return f"atrim=end_sample={target},asetpts=N/SR/TB"
    pad = target - captured
    return f"apad=pad_len={pad},atrim=end_sample={target},asetpts=N/SR/TB"


def _infer_effective_capture_sample_rate(*, captured_frames: int, captured_ticks: int, replay_tick_rate: int) -> int:
    frames = captured_frames
    ticks = captured_ticks
    tick_rate = replay_tick_rate
    fallback_rate = _AUDIO_CAPTURE_SAMPLE_RATE
    if frames <= 0:
        raise ReplayRenderError(
            "invalid audio capture for sample-rate inference: "
            f"captured_frames={frames} captured_ticks={ticks} replay_tick_rate={tick_rate} "
            f"fallback_sample_rate={fallback_rate}",
        )
    if ticks <= 0 or tick_rate <= 0:
        raise ReplayRenderError(
            "invalid replay timing for audio sample-rate inference: "
            f"captured_frames={frames} captured_ticks={ticks} replay_tick_rate={tick_rate} "
            f"fallback_sample_rate={fallback_rate}",
        )
    inferred = round(frames * tick_rate / ticks)
    if _AUDIO_INFERRED_SAMPLE_RATE_MIN <= inferred <= _AUDIO_INFERRED_SAMPLE_RATE_MAX:
        return inferred
    raise ReplayRenderError(
        "inferred effective audio sample rate out of range: "
        f"captured_frames={frames} captured_ticks={ticks} replay_tick_rate={tick_rate} "
        f"inferred_sample_rate={inferred} allowed_range="
        f"{_AUDIO_INFERRED_SAMPLE_RATE_MIN}-{_AUDIO_INFERRED_SAMPLE_RATE_MAX} "
        f"fallback_sample_rate={fallback_rate}",
    )


def _validate_args(*, fps: int, crf: int) -> None:
    if fps <= 0:
        raise ReplayRenderError("fps must be > 0")
    if crf < 0 or crf > 51:
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
        "-y" if overwrite else "-n",
        "-f",
        "rawvideo",
        "-pixel_format",
        "rgba",
        "-video_size",
        f"{width}x{height}",
        "-framerate",
        str(fps),
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
            str(crf),
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
    if return_code == 0:
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
