"""Bound compiler execution, including the Wibo child process tree."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

DEFAULT_COMPILE_TIMEOUT = 120.0
COMPILER_CLEANUP_TIMEOUT = 1.0


def _terminate_compiler(process: subprocess.Popen[str]) -> bool:
    # The wrapper execs Wibo, which can itself have compiler children.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.communicate(timeout=COMPILER_CLEANUP_TIMEOUT)
    except subprocess.TimeoutExpired:
        # A process blocked in the kernel may not act on SIGKILL yet. Also,
        # descendants outside the group can keep the output pipes open.
        return False
    return True


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
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        cleanup_finished = _terminate_compiler(process)
        message = f"compiler timed out after {timeout:.3f}s"
        if not cleanup_finished:
            message += (
                f"; process group {process.pid} cleanup did not finish within "
                f"{COMPILER_CLEANUP_TIMEOUT:.3f}s after SIGKILL"
            )
        raise TimeoutError(message) from exc
    except BaseException:
        _terminate_compiler(process)
        raise
    finally:
        # Popen.__exit__ calls wait() without a timeout. Close our pipe ends
        # explicitly instead, so an unkillable process cannot block unwinding.
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
