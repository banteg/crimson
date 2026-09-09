from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Self
from unittest.mock import Mock

import pytest

from crimson import match_process
from crimson.match_process import run_compiler


def test_compiler_deadline_kills_descendants(tmp_path: Path) -> None:
    child = tmp_path / "child.py"
    marker = tmp_path / "survived"
    child.write_text(f"import time\nfrom pathlib import Path\ntime.sleep(1)\nPath({str(marker)!r}).touch()\n")
    parent = tmp_path / "parent.py"
    ready = tmp_path / "ready"
    parent.write_text(
        "import subprocess, sys, time\nfrom pathlib import Path\n"
        f"subprocess.Popen([sys.executable, {str(child)!r}])\n"
        f"Path({str(ready)!r}).touch()\ntime.sleep(60)\n",
    )
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="timed out"):
        run_compiler([sys.executable, str(parent)], cwd=tmp_path, env=dict(os.environ), deadline=started + 0.5)
    assert time.monotonic() - started < 3
    assert ready.exists()
    time.sleep(1)
    assert not marker.exists()


def test_expired_deadline_does_not_launch_compiler(tmp_path: Path) -> None:
    with pytest.raises(TimeoutError, match="before launch"):
        run_compiler([sys.executable, "-c", "raise SystemExit(99)"], cwd=tmp_path, env={}, deadline=0)


def test_compiler_preserves_output_and_exit_status(tmp_path: Path) -> None:
    result = run_compiler(
        [sys.executable, "-c", "import sys; print('diagnostic', file=sys.stderr); sys.exit(7)"],
        cwd=tmp_path,
        env=dict(os.environ),
    )
    assert result.returncode == 7
    assert result.stderr == "diagnostic\n"


def test_compiler_cleanup_is_bounded_when_descendant_keeps_pipes_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(match_process, "COMPILER_CLEANUP_TIMEOUT", 0.1)
    pid_file = tmp_path / "escaped-child.pid"
    parent = tmp_path / "parent.py"
    parent.write_text(
        "import subprocess, sys, time\nfrom pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
        "start_new_session=True)\n"
        f"Path({str(pid_file)!r}).write_text(str(child.pid))\n"
        "time.sleep(60)\n",
    )
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="cleanup did not finish"):
            run_compiler(
                [sys.executable, str(parent)],
                cwd=tmp_path,
                env=dict(os.environ),
                deadline=started + 0.5,
            )
        assert time.monotonic() - started < 3
        assert pid_file.exists()
    finally:
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_compiler_does_not_wait_forever_for_an_unkillable_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StuckProcess:
        pid = 12345
        stdout = io.StringIO()
        stderr = io.StringIO()

        def communicate(self, *, timeout: float | None = None) -> tuple[str, str]:
            assert timeout is not None
            raise subprocess.TimeoutExpired("stuck-compiler", timeout)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            pytest.fail("Popen.__exit__ would wait indefinitely for the stuck process")

    killpg = Mock()
    process = StuckProcess()
    monkeypatch.setattr(match_process.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(match_process.os, "killpg", killpg)
    with pytest.raises(TimeoutError, match="process group 12345 cleanup did not finish"):
        run_compiler(["stuck-compiler"], cwd=tmp_path, env={})
    killpg.assert_called_once_with(12345, signal.SIGKILL)
    assert process.stdout.closed
    assert process.stderr.closed


def test_compiler_interruption_terminates_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InterruptedProcess:
        pid = 12346
        stdout = io.StringIO()
        stderr = io.StringIO()
        calls = 0

        def communicate(self, *, timeout: float | None = None) -> tuple[str, str]:
            assert timeout is not None
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            return "", ""

    process = InterruptedProcess()
    killpg = Mock()
    monkeypatch.setattr(match_process.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(match_process.os, "killpg", killpg)
    with pytest.raises(KeyboardInterrupt):
        run_compiler(["interrupted-compiler"], cwd=tmp_path, env={})
    killpg.assert_called_once_with(12346, signal.SIGKILL)
    assert process.stdout.closed
    assert process.stderr.closed
