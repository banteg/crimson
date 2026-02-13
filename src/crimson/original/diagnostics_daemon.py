from __future__ import annotations

import argparse
import contextlib
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback

import msgspec

from .diagnostics_cache import (
    DaemonRequest,
    DaemonResponse,
    SessionRegistry,
    cache_enabled,
    idle_timeout_seconds,
    socket_path,
)

_FRAME_LEN_BYTES = 4
_CLIENT_TIMEOUT_SECONDS = 1200.0
_DAEMON_BOOT_TIMEOUT_SECONDS = 8.0


def _encode_frame(payload: bytes) -> bytes:
    return int(len(payload)).to_bytes(_FRAME_LEN_BYTES, byteorder="big", signed=False) + payload


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = int(count)
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("unexpected EOF while reading daemon frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_request_once(
    request: DaemonRequest,
    *,
    timeout_seconds: float,
) -> DaemonResponse:
    sock_path = socket_path()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(float(timeout_seconds))
        sock.connect(str(sock_path))
        payload = msgspec.json.encode(request)
        sock.sendall(_encode_frame(payload))
        header = _recv_exact(sock, _FRAME_LEN_BYTES)
        frame_len = int.from_bytes(header, byteorder="big", signed=False)
        frame = _recv_exact(sock, int(frame_len))
    return msgspec.json.decode(frame, type=DaemonResponse)


def _wait_for_daemon_ready(*, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + float(timeout_seconds)
    while time.monotonic() < deadline:
        if socket_path().exists():
            try:
                probe = DaemonRequest(tool="_ping")
                _send_request_once(probe, timeout_seconds=0.25)
                return True
            except Exception:
                pass
        time.sleep(0.05)
    return False


def _start_daemon_background() -> None:
    sock_path = socket_path()
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.setdefault("CRIMSON_ORIGINAL_CACHE", "1")
    subprocess.Popen(
        [sys.executable, "-m", "crimson.original.diagnostics_daemon", "--serve"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
        env=env,
    )


def run_tool_request(
    *,
    tool: str,
    args: list[str],
    cwd: Path,
) -> DaemonResponse:
    request = DaemonRequest(tool=str(tool), args=[str(arg) for arg in args], cwd=str(cwd))
    try:
        return _send_request_once(request, timeout_seconds=_CLIENT_TIMEOUT_SECONDS)
    except Exception:
        _start_daemon_background()
        if not _wait_for_daemon_ready(timeout_seconds=_DAEMON_BOOT_TIMEOUT_SECONDS):
            raise RuntimeError("diagnostics daemon failed to start")
        return _send_request_once(request, timeout_seconds=_CLIENT_TIMEOUT_SECONDS)


def _parse_capture_path(tool: str, args: list[str]) -> Path | None:
    try:
        if any(str(arg) in {"-h", "--help"} for arg in args):
            return None
        if str(tool) == "divergence-report":
            from . import divergence_report

            parser = divergence_report.build_parser()
        elif str(tool) == "bisect-divergence":
            from . import divergence_bisect

            parser = divergence_bisect.build_parser()
        elif str(tool) == "focus-trace":
            from . import focus_trace

            parser = focus_trace._build_arg_parser()
        else:
            return None
        parser.exit_on_error = False
        parsed = parser.parse_args(list(args))
        capture = getattr(parsed, "capture", None)
        if capture is None:
            return None
        return Path(capture).expanduser().resolve()
    except SystemExit:
        return None
    except Exception:
        return None


@contextlib.contextmanager
def _temporary_cwd(path: Path | None):
    if path is None:
        yield
        return
    prev = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(prev)


@contextlib.contextmanager
def _temporary_argv0(value: str | None):
    if value is None:
        yield
        return
    prev = list(sys.argv)
    if prev:
        sys.argv[0] = str(value)
    else:
        sys.argv = [str(value)]
    try:
        yield
    finally:
        sys.argv = prev


def _run_tool(
    *,
    tool: str,
    args: list[str],
    registry: SessionRegistry,
    cwd: Path | None,
) -> DaemonResponse:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = 1

    with _temporary_cwd(cwd):
        capture_path = _parse_capture_path(str(tool), list(args))
        session = registry.get_session(capture_path) if capture_path is not None else None

        with _temporary_argv0("crimson"), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                if str(tool) == "_ping":
                    exit_code = 0
                elif str(tool) == "divergence-report":
                    from . import divergence_report

                    exit_code = int(divergence_report.main(list(args), session=session))
                elif str(tool) == "bisect-divergence":
                    from . import divergence_bisect

                    exit_code = int(divergence_bisect.main(list(args)))
                elif str(tool) == "focus-trace":
                    from . import focus_trace

                    exit_code = int(focus_trace.main(list(args), session=session))
                else:
                    print(f"unsupported daemon tool: {tool}")
                    exit_code = 2
            except SystemExit as exc:
                code = exc.code
                if isinstance(code, int):
                    exit_code = int(code)
                elif code is None:
                    exit_code = 0
                else:
                    exit_code = 1
            except Exception:
                traceback.print_exc()
                exit_code = 1

    return DaemonResponse(exit_code=int(exit_code), stdout=stdout.getvalue(), stderr=stderr.getvalue())


def _prepare_listening_socket(path: Path) -> socket.socket | None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.2)
                probe.connect(str(path))
            # Existing daemon is alive.
            return None
        except OSError:
            path.unlink(missing_ok=True)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(16)
    server.settimeout(1.0)
    return server


def serve_forever() -> int:
    if not cache_enabled():
        return 0

    sock_path = socket_path()
    server = _prepare_listening_socket(sock_path)
    if server is None:
        return 0

    registry = SessionRegistry()
    idle_seconds = float(idle_timeout_seconds())
    last_activity = time.monotonic()

    try:
        while True:
            if (time.monotonic() - float(last_activity)) >= idle_seconds:
                break
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with conn:
                last_activity = time.monotonic()
                try:
                    header = _recv_exact(conn, _FRAME_LEN_BYTES)
                    frame_len = int.from_bytes(header, byteorder="big", signed=False)
                    frame = _recv_exact(conn, int(frame_len))
                    request = msgspec.json.decode(frame, type=DaemonRequest)
                    cwd = Path(request.cwd).expanduser().resolve() if request.cwd else None
                    response = _run_tool(
                        tool=str(request.tool),
                        args=[str(arg) for arg in request.args],
                        registry=registry,
                        cwd=cwd,
                    )
                except Exception:
                    response = DaemonResponse(
                        exit_code=1,
                        stdout="",
                        stderr=traceback.format_exc(),
                    )

                payload = msgspec.json.encode(response)
                try:
                    conn.sendall(_encode_frame(payload))
                except OSError:
                    pass
    finally:
        with contextlib.suppress(OSError):
            server.close()
        with contextlib.suppress(OSError):
            sock_path.unlink(missing_ok=True)

    return 0


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Crimson original diagnostics cache daemon")
    parser.add_argument("--serve", action="store_true", help="run the daemon server")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    if bool(args.serve):
        return int(serve_forever())
    print("use --serve")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
