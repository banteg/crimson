from __future__ import annotations

import argparse
import csv
import io
import socket
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, List


DEFAULT_CDB = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
DEFAULT_IMAGE = "crimsonland.exe"


@dataclass
class CaptureState:
    active_id: str | None = None
    lines: List[str] = field(default_factory=list)
    event: threading.Event = field(default_factory=threading.Event)


class CdbBridge:
    def __init__(
        self,
        cdb_path: str,
        args: list[str],
        log_path: Path,
        tail_size: int,
    ) -> None:
        self.cdb_path = cdb_path
        self.args = args
        self.log_path = log_path
        self.tail: Deque[str] = deque(maxlen=tail_size)
        self.capture = CaptureState()
        self.lock = threading.Lock()
        self.proc: subprocess.Popen[str] | None = None
        self.log_handle = log_path.open("a", encoding="utf-8")

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [self.cdb_path, *self.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        thread = threading.Thread(target=self._reader, daemon=True)
        thread.start()

    def _reader(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            self._handle_line(line)
        self._handle_line("[cdb] process terminated\n")

    def _handle_line(self, line: str) -> None:
        self.log_handle.write(line)
        self.log_handle.flush()
        self.tail.append(line.rstrip("\n"))
        with self.lock:
            if self.capture.active_id is not None:
                marker = f"__CDB_BRIDGE_DONE__{self.capture.active_id}"
                if marker in line:
                    self.capture.active_id = None
                    self.capture.event.set()
                else:
                    self.capture.lines.append(line.rstrip("\n"))

    def send_command(self, command: str, timeout: float) -> list[str]:
        assert self.proc and self.proc.stdin
        cmd_id = uuid.uuid4().hex[:8]
        marker = f".echo __CDB_BRIDGE_DONE__{cmd_id}"
        with self.lock:
            self.capture.active_id = cmd_id
            self.capture.lines = []
            self.capture.event.clear()
        self.proc.stdin.write(command.rstrip() + "\n")
        self.proc.stdin.write(marker + "\n")
        self.proc.stdin.flush()
        finished = self.capture.event.wait(timeout=timeout)
        with self.lock:
            lines = list(self.capture.lines)
            self.capture.active_id = None
            self.capture.lines = []
            self.capture.event.clear()
        if not finished:
            lines.append("[cdb] command timed out waiting for marker")
        return lines

    def tail_lines(self, count: int) -> list[str]:
        if count <= 0:
            return []
        return list(self.tail)[-count:]

    def close(self) -> None:
        if self.proc and self.proc.stdin:
            try:
                self.proc.stdin.write("q\n")
                self.proc.stdin.flush()
            except BrokenPipeError:
                pass
        if self.proc:
            self.proc.terminate()
        self.log_handle.close()


def serve(
    bridge: CdbBridge,
    host: str,
    port: int,
    timeout: float,
) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    while True:
        conn, _ = server.accept()
        with conn:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            if not data:
                continue
            line = data.decode("utf-8", errors="replace").strip()
            if line.startswith(":tail"):
                parts = line.split()
                count = int(parts[1]) if len(parts) > 1 else 50
                lines = bridge.tail_lines(count)
                payload = "\n".join(lines) + "\n<<<END>>>\n"
                conn.sendall(payload.encode("utf-8"))
                continue
            if line.startswith(":quit"):
                bridge.close()
                conn.sendall(b"OK\n<<<END>>>\n")
                break
            lines = bridge.send_command(line, timeout=timeout)
            payload = "\n".join(lines) + "\n<<<END>>>\n"
            conn.sendall(payload.encode("utf-8"))


def find_pid_by_image(image: str) -> int:
    proc = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {image}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (proc.stdout or "").strip()
    if not output or output.startswith("INFO:"):
        raise SystemExit(f"Process not found for image '{image}'.")
    line = output.splitlines()[0]
    reader = csv.reader(io.StringIO(line))
    parts = next(reader, [])
    if len(parts) < 2 or not parts[1].strip().isdigit():
        raise SystemExit(f"Could not parse PID from tasklist for '{image}'.")
    return int(parts[1].strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge CDB over a TCP socket.")
    parser.add_argument("--pid", type=int, help="attach to PID")
    parser.add_argument("--image", type=str, default=None, help="attach to image name")
    parser.add_argument("--exe", type=str, help="launch executable")
    parser.add_argument("--exe-args", type=str, default="", help="args for executable")
    parser.add_argument("--cdb", type=str, default=DEFAULT_CDB, help="path to cdb.exe")
    parser.add_argument("--log", type=Path, default=Path("analysis/windbg/cdb.log"))
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--tail", type=int, default=400)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--init", type=str, default="", help="init commands to send")
    args = parser.parse_args()

    if not args.pid and not args.exe:
        if args.image is None:
            args.image = DEFAULT_IMAGE
        args.pid = find_pid_by_image(args.image)

    cdb_args = ["-g", "-G"]
    if args.pid:
        cdb_args += ["-p", str(args.pid)]
    if args.exe:
        cdb_args.append(args.exe)
        if args.exe_args:
            cdb_args.append(args.exe_args)

    args.log.parent.mkdir(parents=True, exist_ok=True)

    bridge = CdbBridge(args.cdb, cdb_args, args.log, tail_size=args.tail)
    bridge.start()
    time.sleep(0.5)

    if args.init:
        bridge.send_command(args.init, timeout=args.timeout)

    serve(bridge, args.host, args.port, timeout=args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
