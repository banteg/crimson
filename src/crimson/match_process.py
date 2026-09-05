"""Bound compiler execution, including the Wibo child process tree."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

DEFAULT_COMPILE_TIMEOUT = 120.0


def run_compiler(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    deadline: float | None = None,
) -> subprocess.CompletedProcess[str]:
    timeout = DEFAULT_COMPILE_TIMEOUT
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
    if timeout <= 0:
        raise TimeoutError("compiler deadline expired before launch")
    with subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            # The wrapper execs Wibo, which can itself have compiler children.
            # Kill the session's process group before waiting for pipe EOF.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise TimeoutError(f"compiler timed out after {timeout:.3f}s") from exc
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
