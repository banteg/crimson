from __future__ import annotations

import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from .. import __version__

# Compatibility re-export.
# Legacy LAN lockstep modules continue to import `crimson.net.protocol`.
from .legacy_protocol import *  # noqa: F403


@lru_cache(maxsize=1)
def current_build_id() -> str:
    """Return runtime build id.

    Format:
    - In a git checkout: "<version>+g<short_sha>"
    - In a packaged build (no git): "<version>"
    """
    version = str(__version__)
    try:
        repo_root = Path(__file__).resolve().parents[3]
        git_exe = shutil.which("git")
        if git_exe is None:
            return version
        out = subprocess.check_output(
            [git_exe, "rev-parse", "--short=12", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
        build = out.decode("utf-8", errors="replace").strip()
        if build:
            if "+" in version:
                return f"{version}.g{build}"
            return f"{version}+g{build}"
    except (OSError, subprocess.CalledProcessError):
        return version
    return version
