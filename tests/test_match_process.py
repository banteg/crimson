from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

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
