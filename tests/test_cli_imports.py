from __future__ import annotations

import subprocess
import sys


def test_cli_import_stays_headless() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import crimson.cli; print('pyray' in sys.modules)",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout == "False\n"
    assert completed.stderr == ""
