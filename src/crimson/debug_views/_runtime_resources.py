from __future__ import annotations

from pathlib import Path

from grim.assets import load_runtime_resources, runtime_resources_for, unload_runtime_resources


def ensure_runtime_resources_loaded(assets_dir: Path) -> bool:
    try:
        runtime_resources_for(assets_dir)
    except RuntimeError:
        load_runtime_resources(assets_dir)
        return True
    return False


def release_runtime_resources(assets_dir: Path, *, owned: bool) -> None:
    if not owned:
        return
    try:
        resources = runtime_resources_for(assets_dir)
    except RuntimeError:
        return
    unload_runtime_resources(resources)
