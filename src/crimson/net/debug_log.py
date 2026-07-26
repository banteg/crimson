from __future__ import annotations

import datetime as dt
import os
from collections.abc import Callable
from pathlib import Path
from threading import Lock

_TRACE_LOCK = Lock()
_TRACE_PATH: Path | None = None
_TRACE_FORWARDER: Callable[[str], None] | None = None


def _format_value(value: object) -> str:
    text = str(value)
    return text.replace("\n", "\\n")


def _format_fields(fields: dict[str, object]) -> str:
    parts: list[str] = []
    for key in sorted(fields):
        parts.append(f"{key}={_format_value(fields[key])}")
    return " ".join(parts)


def lan_debug_log_path() -> Path | None:
    with _TRACE_LOCK:
        return _TRACE_PATH


def set_lan_debug_forwarder(forwarder: Callable[[str], None] | None) -> None:
    """Install a callback that receives each formatted debug log line.

    This is used by LAN clients to mirror their debug logs to the host for easier
    cross-machine analysis. The callback is invoked outside the file lock.
    """
    with _TRACE_LOCK:
        global _TRACE_FORWARDER
        _TRACE_FORWARDER = forwarder


def init_lan_debug_log(
    *,
    base_dir: Path,
    role: str,
    mode: str,
    build_id: str,
    host: str,
    port: int,
    player_count: int,
    auto_start: bool,
    debug_enabled: bool,
) -> Path:
    role_name = str(role).strip().lower() or "unknown"
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    path = base_dir / "logs" / "lan" / f"lan-{role_name}-pid{os.getpid()}-{timestamp}.log"
    path.parent.mkdir(parents=True, exist_ok=True)

    with _TRACE_LOCK:
        global _TRACE_PATH
        _TRACE_PATH = path

    lan_debug_log(
        "init",
        role=role_name,
        mode=str(mode),
        build_id=str(build_id),
        host=str(host),
        port=int(port),
        player_count=int(player_count),
        auto_start=bool(auto_start),
        debug=bool(debug_enabled),
        pid=int(os.getpid()),
    )
    return path


def lan_debug_log(event: str, **fields: object) -> None:
    timestamp = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
    payload = _format_fields(fields)
    line = f"{timestamp} event={str(event).strip()}"
    if payload:
        line += f" {payload}"
    line += "\n"

    forwarder: Callable[[str], None] | None
    with _TRACE_LOCK:
        path = _TRACE_PATH
        forwarder = _TRACE_FORWARDER
        if path is None:
            return
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)

    if forwarder is not None:
        forwarder(str(line))


def close_lan_debug_log() -> None:
    with _TRACE_LOCK:
        global _TRACE_PATH
        _TRACE_PATH = None
        global _TRACE_FORWARDER
        _TRACE_FORWARDER = None


__all__ = [
    "close_lan_debug_log",
    "init_lan_debug_log",
    "lan_debug_log",
    "lan_debug_log_path",
    "set_lan_debug_forwarder",
]
