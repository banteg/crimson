from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import cast

from crimson.dbg.frida_finalize import (
    FRIDA_RUNTIME_VERSION,
    FridaFinalizeError,
    finalize_frida_jsonl_to_traces,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Attach to gameplay_diff_capture.js, stop capture on shutdown, then "
            "finalize raw JSONL capture into one or more .cdt/.crd run artifacts."
        ),
    )
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "--process",
        default="crimsonland.exe",
        help="target process name (default: crimsonland.exe)",
    )
    target_group.add_argument("--pid", type=int, default=None, help="target process id")
    parser.add_argument(
        "--script",
        type=Path,
        default=Path("scripts/frida/gameplay_diff_capture.js"),
        help="path to gameplay_diff_capture.js",
    )
    parser.add_argument(
        "--raw-path",
        type=Path,
        default=None,
        help="raw JSONL path injected into the agent (default: CRIMSON_FRIDA_OUT_PATH or standard share path)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="directory for finalized .cdt/.crd files (default: raw capture parent)",
    )
    parser.add_argument(
        "--keep-raw",
        action="store_true",
        help="keep raw JSONL file after successful finalize",
    )
    parser.add_argument(
        "--finalize-only",
        action="store_true",
        help="skip attaching; finalize an existing raw JSONL (use with --raw-path)",
    )
    return parser


def _default_raw_capture_path() -> Path:
    env_out = os.environ.get("CRIMSON_FRIDA_OUT_PATH")
    if env_out:
        return Path(env_out)
    base_dir = Path(os.environ.get("CRIMSON_FRIDA_DIR", "C:\\share\\frida"))
    return base_dir / "gameplay_diff_capture.jsonl"


def _normalized_path(path: Path) -> str:
    return os.path.normcase(str(Path(path).expanduser().resolve(strict=False)))


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.finalize_only:
        if args.raw_path is None:
            parser.error("--finalize-only requires --raw-path")
        return _finalize_and_report(
            args,
            raw_path=Path(args.raw_path).expanduser().resolve(strict=False),
            stats={},
            failure=[],
            start_ts=time.time(),
        )

    script_path = Path(args.script)
    if not script_path.is_file():
        print(f"[capture-host] script not found: {script_path}", file=sys.stderr)
        return 2

    try:
        import frida
    except ImportError as exc:
        print(
            "[capture-host] missing dependency: frida. "
            f"Run with `uv run --with frida=={FRIDA_RUNTIME_VERSION} python "
            "scripts/frida/gameplay_diff_capture_host.py ...`.",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
    frida_version = importlib.metadata.version("frida")
    if frida_version != FRIDA_RUNTIME_VERSION:
        print(
            f"[capture-host] unsupported frida={frida_version}; expected {FRIDA_RUNTIME_VERSION}",
            file=sys.stderr,
        )
        return 2
    print(f"[capture-host] frida={frida_version}", flush=True)

    raw_path = (
        (Path(args.raw_path) if args.raw_path is not None else _default_raw_capture_path())
        .expanduser()
        .resolve(strict=False)
    )
    try:
        raw_path.unlink(missing_ok=True)
    except OSError as exc:
        print(f"[capture-host] cannot clear raw capture {raw_path}: {exc}", file=sys.stderr)
        return 2

    stop_event = threading.Event()
    failure: list[str] = []
    start_ts = time.time()

    device = frida.get_local_device()  # ty: ignore[unresolved-attribute]
    target = int(args.pid) if args.pid is not None else str(args.process)
    print(f"[capture-host] attaching target={target}", flush=True)
    session = device.attach(target)
    host_config_json = json.dumps({"out_path": str(raw_path)})
    script_source = (
        '"use strict";\n'
        f"globalThis.CRIMSON_CAPTURE_HOST_CONFIG = {host_config_json};\n" + script_path.read_text(encoding="utf-8")
    )
    script = session.create_script(script_source)

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
        if message_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                payload_dict = cast(dict[str, object], payload)
                payload_event = payload_dict.get("event")
                payload_error = payload_dict.get("error")
            else:
                payload_event = None
                payload_error = None
            if payload_event == "capture_startup_error":
                failure.append(f"agent startup failed: {payload_error or 'unknown'}")
                stop_event.set()
                return
            if payload_event == "capture_runtime_error":
                failure.append(f"agent runtime failed: {payload_error or 'unknown'}")
                stop_event.set()
                return
        if data is not None:
            _ = len(data)

    def on_detached(*info: object) -> None:
        reason = str(info[0]) if info else "unknown"
        print(f"[capture-host] detached reason={reason}", flush=True)
        if len(info) > 1:
            extra = [repr(item) for item in info[1:] if item is not None]
            if extra:
                print(f"[capture-host] detached extra={' | '.join(extra)}", flush=True)
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

    stats: dict[str, object] = {}
    try:
        while not stop_event.wait(timeout=0.25):
            pass
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        try:
            try:
                stopped_ticks = script.exports_sync.stop("host_shutdown")
                print(f"[capture-host] agent stopped ticks={stopped_ticks}", flush=True)
            except Exception as exc:
                print(f"[capture-host] agent stop unavailable: {exc}", file=sys.stderr, flush=True)
            try:
                stats_obj = script.exports_sync.stats()
                if isinstance(stats_obj, dict):
                    stats = dict(stats_obj)
                    out_path_obj = stats.get("out_path")
                    if not isinstance(out_path_obj, str) or not out_path_obj.strip():
                        failure.append("agent stats missing out_path")
                    elif _normalized_path(Path(out_path_obj.strip())) != _normalized_path(raw_path):
                        failure.append(
                            f"agent out_path={out_path_obj.strip()!r} does not match expected {str(raw_path)!r}",
                        )
            except Exception as exc:
                print(f"[capture-host] agent stats unavailable: {exc}", file=sys.stderr, flush=True)
                stats = {}
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

    return _finalize_and_report(
        args,
        raw_path=raw_path,
        stats=stats,
        failure=failure,
        start_ts=start_ts,
    )


def _finalize_and_report(
    args: argparse.Namespace,
    *,
    raw_path: Path,
    stats: dict[str, object],
    failure: list[str],
    start_ts: float,
) -> int:
    last_exception = stats.get("last_exception")
    if isinstance(last_exception, dict) and last_exception:
        print(f"[capture-host] last_exception={last_exception}", flush=True)
        failure.append(f"agent process exception: {last_exception}")
    capture_failure = stats.get("capture_failure")
    if isinstance(capture_failure, dict) and capture_failure:
        failure.append(f"agent capture failure: {capture_failure}")
    last_hook = stats.get("last_hook")
    if isinstance(last_hook, dict) and last_hook:
        print(f"[capture-host] last_hook={last_hook}", flush=True)
    if failure:
        result = None
    else:
        print(f"[capture-host] finalizing raw={raw_path}", flush=True)
        try:
            result = finalize_frida_jsonl_to_traces(
                raw_path,
                output_dir=(None if args.output_dir is None else Path(args.output_dir)),
                delete_raw=(not bool(args.keep_raw)),
            )
        except FridaFinalizeError as exc:
            failure.append(f"finalize failed: {exc}")
            result = None

    elapsed = max(0.0, time.time() - start_ts)
    if result is not None:
        trace_count = len(result.traces)
        total_ticks = sum(int(trace.tick_count) for trace in result.traces)
        print(
            f"[capture-host] finalized traces={trace_count} ticks={total_ticks} deleted_raw={result.deleted_raw}",
            flush=True,
        )
        for trace in result.traces:
            print(
                f"[capture-host] trace={trace.out_path} run_id={trace.run_id} "
                f"replay={trace.replay_path} "
                f"ticks={trace.tick_count} mode={trace.mode_id} "
                f"quest={trace.quest_stage_major}.{trace.quest_stage_minor}",
                flush=True,
            )
    print(f"[capture-host] done elapsed_s={elapsed:.2f}", flush=True)

    if failure:
        print("[capture-host] errors:", file=sys.stderr)
        for item in failure:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
