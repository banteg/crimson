from __future__ import annotations

import os
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import msgspec

from grim import paq
from grim.console import ConsoleState

ASSET_BASE_URL = "https://paq.crimson.banteg.xyz/v1.9.93"
DEFAULT_PAQ_FILES = ("crimson.paq", "music.paq", "sfx.paq")
MUSIC_PAQ = "music.paq"


class DownloadResult(msgspec.Struct, frozen=True):
    name: str
    ok: bool
    error: str | None = None


def _download_file(url: str, dest: Path) -> None:
    tmp_path: Path | None = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "crimsonland-decompile"})
        with urllib.request.urlopen(req, timeout=30) as resp, tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            dir=dest.parent,
            prefix=dest.name + ".",
            suffix=".tmp",
        ) as handle:
            tmp_path = Path(handle.name)
            shutil.copyfileobj(resp, handle)
            handle.flush()
            os.fsync(handle.fileno())
        if tmp_path is None:
            raise RuntimeError("assets: temporary file not created")
        tmp_path.replace(dest)
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def download_missing_paqs(
    assets_dir: Path,
    console: ConsoleState,
    *,
    base_url: str = ASSET_BASE_URL,
    names: tuple[str, ...] = DEFAULT_PAQ_FILES,
) -> tuple[DownloadResult, ...]:
    assets_dir.mkdir(parents=True, exist_ok=True)
    missing = [name for name in names if not (assets_dir / name).is_file()]
    if not missing:
        return ()
    console.log.log(f"assets: missing {', '.join(missing)} (downloading)")
    results: list[DownloadResult] = []
    for name in missing:
        url = f"{base_url}/{name}"
        dest = assets_dir / name
        try:
            _download_file(url, dest)
        except (OSError, RuntimeError, urllib.error.URLError) as exc:
            results.append(DownloadResult(name=name, ok=False, error=str(exc)))
            console.log.log(f"assets: failed to download {name}: {exc}")
            continue
        results.append(DownloadResult(name=name, ok=True))
        console.log.log(f"assets: downloaded {name}")
    console.log.flush()
    return tuple(results)


def music_entry_name(name: str) -> str:
    """The name the original asks music.paq for: `music\\<file>`."""
    return "music\\" + name.replace("\\", "/").rsplit("/", 1)[-1]


def migrate_music_paq(assets_dir: Path) -> bool:
    """Rename an earlier repack's entries (`intro.ogg`, `music/game_tunes.txt`) to the names the original asks for.

    The native and web clients run the original's own pack lookup, which matches whole names.
    """
    path = assets_dir / MUSIC_PAQ
    if not path.is_file():
        return False
    entries = paq.read_paq(path)
    renamed = [(music_entry_name(name), data) for name, data in entries]
    if renamed == entries:
        return False
    tmp_path = path.with_name(path.name + ".tmp")
    paq.write_paq(tmp_path, renamed)
    tmp_path.replace(path)
    return True
