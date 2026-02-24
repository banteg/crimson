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
import gzip
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
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


def _iter_json_stream_rows(path: Path) -> Any:
    lower = str(path).lower()
    if lower.endswith(".json.gz"):
        with gzip.open(path, "rb") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                yield msgspec.json.decode(line)
        return
    if lower.endswith(".json"):
        with path.open("rb") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                yield msgspec.json.decode(line)
        return
    raise ValueError(f"unsupported json capture input: {path}")


@dataclass
class PostpackSummary:
    input_path: Path
    output_path: Path
    rows: int
    ticks: int


def _convert_json_capture_to_msgpack(
    *,
    input_path: Path,
    output_path: Path,
    zstd_level: int | None,
    flush_every: int,
) -> PostpackSummary:
    rows = 0
    ticks = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if zstd_level is None:
        compressor = zstd.ZstdCompressor()
    else:
        compressor = zstd.ZstdCompressor(level=int(zstd_level))

    with output_path.open("wb") as out_file:
        with compressor.stream_writer(out_file) as stream:
            stream.write(_MSGPACK_STREAM_MAGIC)
            stream.flush(zstd.FLUSH_BLOCK)
            for row in _iter_json_stream_rows(input_path):
                payload = msgspec.msgpack.encode(row)
                stream.write(len(payload).to_bytes(_MSGPACK_LEN_BYTES, "little", signed=False))
                stream.write(payload)
                rows += 1
                if isinstance(row, dict) and row.get("event") == "tick":
                    ticks += 1
                if rows % max(1, int(flush_every)) == 0:
                    stream.flush(zstd.FLUSH_BLOCK)
            stream.flush(zstd.FLUSH_FRAME)

    return PostpackSummary(
        input_path=Path(input_path),
        output_path=Path(output_path),
        rows=int(rows),
        ticks=int(ticks),
    )


def _resolve_capture_dirs(output_dir: Path | None) -> list[Path]:
    base_dir = Path(output_dir) if output_dir is not None else Path(os.environ.get("CRIMSON_FRIDA_DIR", "C:\\share\\frida"))
    dirs: list[Path] = [base_dir]

    quest_dir_raw = os.environ.get("CRIMSON_FRIDA_QUEST_OUT_DIR")
    if quest_dir_raw:
        dirs.append(Path(quest_dir_raw))

    out_path_raw = os.environ.get("CRIMSON_FRIDA_OUT_PATH")
    if out_path_raw:
        dirs.append(Path(out_path_raw).parent)

    unique: list[Path] = []
    seen: set[str] = set()
    for item in dirs:
        key = str(item)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _list_capture_json_files(dirs: list[Path]) -> list[Path]:
    found: dict[str, Path] = {}
    for directory in dirs:
        for pattern in ("gameplay_diff_capture*.json", "gameplay_diff_capture*.json.gz"):
            for path in directory.glob(pattern):
                if not path.is_file():
                    continue
                found[str(path)] = path
    return sorted(found.values())


def _snapshot_capture_json_files(dirs: list[Path]) -> dict[Path, int]:
    snapshot: dict[Path, int] = {}
    for path in _list_capture_json_files(dirs):
        try:
            snapshot[path] = int(path.stat().st_mtime_ns)
        except OSError:
            continue
    return snapshot


def _collect_changed_capture_json_files(*, dirs: list[Path], before: dict[Path, int]) -> list[Path]:
    changed: list[Path] = []
    for path in _list_capture_json_files(dirs):
        try:
            mtime_ns = int(path.stat().st_mtime_ns)
        except OSError:
            continue
        prev = before.get(path)
        if prev is None or mtime_ns > int(prev):
            changed.append(path)
    return sorted(changed)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Attach to gameplay_diff_capture.js with file sink, then post-convert "
            "newly written gameplay_diff_capture*.json/.json.gz files to framed msgpack.zst."
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
        help="capture output directory to watch (default: CRIMSON_FRIDA_DIR or C:\\share\\frida)",
    )
    parser.add_argument(
        "--zstd-level",
        type=int,
        default=None,
        help="zstd compression level for postpack output (default: library default)",
    )
    parser.add_argument(
        "--flush-every",
        type=int,
        default=1,
        help="flush compressed stream every N rows while postpacking (default: 1)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    script_path = Path(args.script)
    if not script_path.is_file():
        print(f"[capture-postpack] script not found: {script_path}", file=sys.stderr)
        return 2

    try:
        import frida
    except ImportError as exc:
        print(
            "[capture-postpack] missing dependency: frida. "
            "Run with `uv run --with frida scripts/frida/gameplay_diff_capture_postpack.py ...`.",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc

    watch_dirs = _resolve_capture_dirs(None if args.output_dir is None else Path(args.output_dir))
    for item in watch_dirs:
        item.mkdir(parents=True, exist_ok=True)

    before = _snapshot_capture_json_files(watch_dirs)
    print("[capture-postpack] watching dirs:", ", ".join(str(p) for p in watch_dirs), flush=True)

    stop_event = threading.Event()
    failure: list[str] = []
    start_ts = time.time()

    device = frida.get_local_device()
    target = int(args.pid) if args.pid is not None else str(args.process)
    print(f"[capture-postpack] attaching target={target}", flush=True)
    session = device.attach(target)
    script_source = script_path.read_text(encoding="utf-8")
    script_prelude = 'globalThis.__CRIMSON_FRIDA_CAPTURE_SINK = "file";\n'
    script = session.create_script(script_prelude + script_source)

    def on_message(message: dict[str, object], data: bytes | None) -> None:
        message_type = message.get("type")
        if message_type == "error":
            stack = message.get("stack")
            if isinstance(stack, str):
                failure.append(stack)
            else:
                failure.append(str(message))
            stop_event.set()
            return
        if data is not None:
            _ = len(data)

    def on_detached(*info: object) -> None:
        reason = str(info[0]) if info else "unknown"
        print(f"[capture-postpack] detached reason={reason}", flush=True)
        stop_event.set()

    session.on("detached", on_detached)
    script.on("message", on_message)
    script.load()
    print("[capture-postpack] script loaded", flush=True)

    def _handle_signal(signum: int, _frame: object) -> None:
        print(f"[capture-postpack] signal={signum} stopping capture", flush=True)
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

    changed = _collect_changed_capture_json_files(dirs=watch_dirs, before=before)
    print(f"[capture-postpack] changed json captures={len(changed)}", flush=True)

    summaries: list[PostpackSummary] = []
    for json_path in changed:
        out_path = json_path.with_name(_derive_msgpack_name(json_path.name))
        try:
            summary = _convert_json_capture_to_msgpack(
                input_path=json_path,
                output_path=out_path,
                zstd_level=(None if args.zstd_level is None else int(args.zstd_level)),
                flush_every=int(args.flush_every),
            )
        except Exception as exc:
            failure.append(f"postpack failed for {json_path}: {exc}")
            continue
        try:
            json_path.unlink()
        except OSError as exc:
            failure.append(f"postpack succeeded but failed deleting source {json_path}: {exc}")
            continue
        summaries.append(summary)
        print(
            f"[capture-postpack] converted {summary.input_path} -> {summary.output_path} "
            f"rows={summary.rows} ticks={summary.ticks}",
            flush=True,
        )

    elapsed = max(0.0, time.time() - start_ts)
    print(
        f"[capture-postpack] done files={len(summaries)} elapsed_s={elapsed:.2f}",
        flush=True,
    )

    if failure:
        print("[capture-postpack] errors:", file=sys.stderr)
        for item in failure:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
