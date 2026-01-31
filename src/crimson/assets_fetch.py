from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import urllib.request

from grim.console import ConsoleState

ASSET_BASE_URL = "https://paq.crimson.banteg.xyz/v1.9.93"
DEFAULT_PAQ_FILES = ("crimson.paq", "music.paq", "sfx.paq")


@dataclass(frozen=True, slots=True)
class DownloadResult:
    name: str
    ok: bool
    error: str | None = None


def _download_file(url: str, dest: Path) -> None:
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "crimsonland-decompile"})
        with urllib.request.urlopen(req, timeout=30) as resp, tmp.open("wb") as handle:
            shutil.copyfileobj(resp, handle)
        tmp.replace(dest)
    finally:
        if tmp.exists():
            tmp.unlink()


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
        except Exception as exc:
            results.append(DownloadResult(name=name, ok=False, error=str(exc)))
            console.log.log(f"assets: failed to download {name}: {exc}")
            continue
        results.append(DownloadResult(name=name, ok=True))
        console.log.log(f"assets: downloaded {name}")
    console.log.flush()
    return tuple(results)
