from __future__ import annotations

from pathlib import Path
import os

from platformdirs import PlatformDirs

APP_NAME = "crimsonland"


def default_runtime_dir() -> Path:
    """Return the default per-user runtime directory.

    This is intended for saves/config/logs (e.g. `game.cfg`, `crimson.cfg`, highscores).
    Override with `CRIMSON_RUNTIME_DIR` (or legacy `CRIMSON_BASE_DIR`).
    """

    override = os.environ.get("CRIMSON_RUNTIME_DIR") or os.environ.get("CRIMSON_BASE_DIR")
    if override:
        return Path(override).expanduser()

    dirs = PlatformDirs(appname=APP_NAME, appauthor=False)
    return Path(dirs.user_data_path)
