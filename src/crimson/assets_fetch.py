from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import msgspec

from grim import paq
from grim.atomic_write import atomic_write_bytes
from grim.console import ConsoleState

ASSET_BASE_URL = "https://paq.crimson.banteg.xyz/v1.9.93"
DEFAULT_PAQ_FILES = ("crimson.paq", "music.paq", "sfx.paq")
MUSIC_PAQ = "music.paq"
ART_VERSION = json.loads(Path(__file__).with_name("assets_version.json").read_text())
CRIMSON_PAQ_SHA256: str = ART_VERSION["current"]
PREVIOUS_CRIMSON_PAQ_SHA256 = frozenset(ART_VERSION["previous"])


class DownloadResult(msgspec.Struct, frozen=True):
    name: str
    ok: bool
    error: str | None = None
    usable_previous: bool = False


def _download_file(url: str, dest: Path, *, expected_sha256: str | None = None) -> None:
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
        if expected_sha256 is not None:
            with tmp_path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != expected_sha256:
                raise RuntimeError(f"assets: {dest.name} has unexpected SHA-256 {digest}")
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
    pins = {"crimson.paq": CRIMSON_PAQ_SHA256, **ART_VERSION["audio"]}
    needed = []
    upgrades = set()
    for name in names:
        path = assets_dir / name
        if not path.is_file():
            needed.append(name)
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest == pins[name]:
            continue
        if name == "crimson.paq" and digest in PREVIOUS_CRIMSON_PAQ_SHA256:
            needed.append(name)
            upgrades.add(name)
            continue
        # A valid original or custom pack belongs to the player. A damaged
        # file from an earlier client remains recoverable after repair.
        try:
            for _ in paq.iter_entries_bytes(data):
                pass
        except ValueError:
            backup = path.with_name(f"{name}.invalid-{digest}")
            if not backup.exists():
                atomic_write_bytes(backup, data)
            console.log.log(f"assets: repairing {name}; original bytes kept in {backup.name}")
            needed.append(name)
    if not needed:
        return ()
    console.log.log(f"assets: downloading {', '.join(needed)}")
    results: list[DownloadResult] = []
    for name in needed:
        expected_sha256 = pins[name]
        url = f"{base_url}/{name}?sha256={expected_sha256}"
        dest = assets_dir / name
        try:
            _download_file(url, dest, expected_sha256=expected_sha256)
        except (OSError, RuntimeError, urllib.error.URLError) as exc:
            results.append(DownloadResult(name=name, ok=False, error=str(exc), usable_previous=name in upgrades))
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
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != ART_VERSION["legacy_music"]:
        return False
    entries = list(paq.iter_entries_bytes(data))
    renamed = [(music_entry_name(name), data) for name, data in entries]
    replacement = paq.build_entries(renamed)
    if hashlib.sha256(replacement).hexdigest() != ART_VERSION["audio"][MUSIC_PAQ]:
        raise ValueError("Recognized music pack did not migrate to the pinned release")
    atomic_write_bytes(path, replacement)
    return True
