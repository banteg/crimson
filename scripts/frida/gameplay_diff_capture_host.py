# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "frida>=16.5.0",
#   "msgspec>=0.20.0",
#   "zstandard>=0.25.0",
# ]
# ///
from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

import msgspec
import zstandard as zstd

_MSGPACK_STREAM_MAGIC = b"crimson_capture_msgpack_v1\n"
_MSGPACK_LEN_BYTES = 4


def _derive_msgpack_name(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".msgpack.zst"):
        return name
    if lower.endswith(".json.gz"):
        stem = name[: -len(".json.gz")]
    elif lower.endswith(".json"):
        stem = name[: -len(".json")]
    else:
        stem = name
    return f"{stem}.msgpack.zst"


def _coerce_out_path_name(source_out_path: str) -> str:
    win_path = PureWindowsPath(str(source_out_path))
    if win_path.name:
        return str(win_path.name)
    path = Path(str(source_out_path))
    if path.name:
        return str(path.name)
    return str(source_out_path)


@dataclass
class WriterSummary:
    source_out_path: str
    output_path: Path
    rows: int
    ticks: int


class CaptureStreamWriter:
    def __init__(
        self,
        *,
        source_out_path: str,
        output_path: Path,
        zstd_level: int | None,
        flush_every: int,
    ) -> None:
        self.source_out_path = str(source_out_path)
        self.output_path = Path(output_path)
        self.zstd_level = zstd_level
        self.flush_every = max(1, int(flush_every))
        self._rows = 0
        self._ticks = 0
        self._file: Any = None
        self._compressor: Any = None
        self._stream: Any = None
        self._open()

    def _open(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.output_path.open("wb")
        if self.zstd_level is None:
            self._compressor = zstd.ZstdCompressor()
        else:
            self._compressor = zstd.ZstdCompressor(level=int(self.zstd_level))
        self._stream = self._compressor.stream_writer(self._file)
        self._stream.write(_MSGPACK_STREAM_MAGIC)
        self._stream.flush(zstd.FLUSH_BLOCK)

    def write_row(self, row: object) -> None:
        if self._stream is None:
            raise RuntimeError("writer is closed")
        payload = msgspec.msgpack.encode(row)
        self._stream.write(len(payload).to_bytes(_MSGPACK_LEN_BYTES, "little", signed=False))
        self._stream.write(payload)
        self._rows += 1
        if isinstance(row, dict) and row.get("event") == "tick":
            self._ticks += 1
        if self._rows % self.flush_every == 0:
            self._stream.flush(zstd.FLUSH_BLOCK)

    def close(self) -> WriterSummary:
        stream = self._stream
        file_handle = self._file
        self._stream = None
        self._file = None
        self._compressor = None
        if stream is not None:
            stream.flush(zstd.FLUSH_FRAME)
            stream.close()
        if file_handle is not None:
            file_handle.close()
        return WriterSummary(
            source_out_path=self.source_out_path,
            output_path=self.output_path,
            rows=int(self._rows),
            ticks=int(self._ticks),
        )


class CaptureHost:
    def __init__(
        self,
        *,
        output_dir: Path | None,
        zstd_level: int | None,
        flush_every: int,
        tick_log_interval: int,
    ) -> None:
        self.output_dir = output_dir
        self.zstd_level = zstd_level
        self.flush_every = max(1, int(flush_every))
        self.tick_log_interval = max(1, int(tick_log_interval))
        self.current_source_out_path: str | None = None
        self.current_writer: CaptureStreamWriter | None = None
        self.summaries: list[WriterSummary] = []
        self.total_rows = 0
        self.total_ticks = 0
        self.last_tick_index: int | None = None

    def _resolve_output_path(self, source_out_path: str) -> Path:
        output_name = _derive_msgpack_name(_coerce_out_path_name(str(source_out_path)))
        if self.output_dir is not None:
            return Path(self.output_dir) / output_name
        if sys.platform.startswith("win"):
            source_path = Path(str(source_out_path))
            return source_path.with_name(output_name)
        return Path(output_name)

    def _switch_writer(self, source_out_path: str) -> None:
        source_key = str(source_out_path)
        if self.current_source_out_path == source_key and self.current_writer is not None:
            return
        if self.current_writer is not None:
            summary = self.current_writer.close()
            self.summaries.append(summary)
            print(
                f"[capture-host] closed {summary.output_path} rows={summary.rows} ticks={summary.ticks}",
                flush=True,
            )
            self.current_writer = None
            self.current_source_out_path = None

        output_path = self._resolve_output_path(source_key)
        self.current_writer = CaptureStreamWriter(
            source_out_path=source_key,
            output_path=output_path,
            zstd_level=self.zstd_level,
            flush_every=self.flush_every,
        )
        self.current_source_out_path = source_key
        print(
            f"[capture-host] opened {output_path} (source={source_key})",
            flush=True,
        )

    def handle_row(self, row: object) -> None:
        if not isinstance(row, dict):
            raise TypeError("capture row payload must be an object")
        event = row.get("event")
        if not isinstance(event, str):
            raise TypeError("capture row missing string event")

        if event == "capture_meta":
            capture = row.get("capture")
            if not isinstance(capture, dict):
                raise ValueError("capture_meta row missing capture object")
            out_path = capture.get("out_path")
            if not isinstance(out_path, str) or not out_path.strip():
                raise ValueError("capture_meta row missing capture.out_path")
            self._switch_writer(out_path.strip())

        if self.current_writer is None:
            raise ValueError(f"received {event!r} before capture_meta row")

        self.current_writer.write_row(row)
        self.total_rows += 1

        if event == "tick":
            self.total_ticks += 1
            tick = row.get("tick")
            if isinstance(tick, dict):
                tick_index = tick.get("tick_index")
                if isinstance(tick_index, int):
                    self.last_tick_index = int(tick_index)
            if self.total_ticks % self.tick_log_interval == 0:
                print(
                    f"[capture-host] ticks={self.total_ticks} last_tick={self.last_tick_index}",
                    flush=True,
                )

    def close(self) -> list[WriterSummary]:
        if self.current_writer is not None:
            summary = self.current_writer.close()
            self.summaries.append(summary)
            self.current_writer = None
            self.current_source_out_path = None
            print(
                f"[capture-host] closed {summary.output_path} rows={summary.rows} ticks={summary.ticks}",
                flush=True,
            )
        return list(self.summaries)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Attach to gameplay_diff_capture.js, consume capture rows via Frida messaging, "
            "and write framed msgpack compressed with zstd."
        ),
    )
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--process", default="crimsonland.exe", help="target process name (default: crimsonland.exe)")
    target_group.add_argument("--pid", type=int, default=None, help="target process id")
    parser.add_argument(
        "--script",
        type=Path,
        default=Path("scripts/frida/gameplay_diff_capture.js"),
        help="path to gameplay_diff_capture.js",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="override output directory for capture files (default: script-provided out_path)",
    )
    parser.add_argument(
        "--zstd-level",
        type=int,
        default=None,
        help="zstd compression level (default: library default)",
    )
    parser.add_argument(
        "--flush-every",
        type=int,
        default=1,
        help="flush compressed stream every N rows (default: 1)",
    )
    parser.add_argument(
        "--tick-log-interval",
        type=int,
        default=250,
        help="print progress every N ticks (default: 250)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    script_path = Path(args.script)
    if not script_path.is_file():
        print(f"[capture-host] script not found: {script_path}", file=sys.stderr)
        return 2

    try:
        import frida
    except ImportError as exc:
        print(
            "[capture-host] missing dependency: frida. "
            "Run with `uv run --with frida scripts/frida/gameplay_diff_capture_host.py ...`.",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc

    host = CaptureHost(
        output_dir=(None if args.output_dir is None else Path(args.output_dir)),
        zstd_level=(None if args.zstd_level is None else int(args.zstd_level)),
        flush_every=int(args.flush_every),
        tick_log_interval=int(args.tick_log_interval),
    )

    stop_event = threading.Event()
    failure: list[str] = []
    start_ts = time.time()

    device = frida.get_local_device()
    target = int(args.pid) if args.pid is not None else str(args.process)
    print(f"[capture-host] attaching target={target}", flush=True)
    session = device.attach(target)
    script = session.create_script(script_path.read_text(encoding="utf-8"))

    def on_message(message: dict[str, object], data: bytes | None) -> None:
        message_type = message.get("type")
        if message_type == "send":
            payload = message.get("payload")
            if not isinstance(payload, dict):
                return
            if payload.get("kind") != "capture_row":
                return
            row = payload.get("row")
            try:
                host.handle_row(row)
            except Exception as exc:
                failure.append(f"row handling error: {exc}")
                stop_event.set()
            return
        if message_type == "error":
            stack = message.get("stack")
            if isinstance(stack, str):
                failure.append(stack)
            else:
                failure.append(str(message))
            stop_event.set()
            return
        if data is not None:
            # No binary side-channel is expected for this capture.
            _ = len(data)

    def on_detached(*info: object) -> None:
        reason = str(info[0]) if info else "unknown"
        print(f"[capture-host] detached reason={reason}", flush=True)
        stop_event.set()

    session.on("detached", on_detached)
    script.on("message", on_message)
    script.load()
    print("[capture-host] script loaded", flush=True)

    def _handle_signal(signum: int, _frame: object) -> None:
        print(f"[capture-host] signal={signum} stopping capture", flush=True)
        stop_event.set()

    old_sigint = signal.getsignal(signal.SIGINT)
    old_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        while not stop_event.wait(timeout=0.25):
            pass
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        try:
            try:
                script.exports_sync.stop("host_shutdown")
            except Exception:
                pass
            time.sleep(0.15)
            try:
                script.unload()
            except Exception:
                pass
            try:
                session.detach()
            except Exception:
                pass
        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)

    summaries = host.close()
    elapsed = max(0.0, time.time() - start_ts)
    print(
        f"[capture-host] done rows={host.total_rows} ticks={host.total_ticks} "
        f"files={len(summaries)} elapsed_s={elapsed:.2f}",
        flush=True,
    )
    for row in summaries:
        print(
            f"[capture-host] file={row.output_path} rows={row.rows} ticks={row.ticks}",
            flush=True,
        )

    if failure:
        print("[capture-host] errors:", file=sys.stderr)
        for item in failure:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
