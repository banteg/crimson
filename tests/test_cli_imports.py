from __future__ import annotations

import subprocess
import sys


def _run(code: str) -> str:
    completed = subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, text=True)
    assert completed.stderr == ""
    return completed.stdout


def test_cli_import_stays_headless() -> None:
    assert _run("import sys; import crimson.cli.app; print('pyray' in sys.modules)") == "False\n"


def test_development_commands_load_no_game_code() -> None:
    loaded = _run(
        "import contextlib, io, sys\n"
        "from crimson.cli import main\n"
        "with contextlib.suppress(SystemExit), contextlib.redirect_stdout(io.StringIO()):\n"
        "    main(['match', '--help'])\n"
        "print(sorted(m for m in sys.modules if m.startswith(('crimson.', 'grim'))))",
    )

    assert loaded == "['crimson.cli']\n"
