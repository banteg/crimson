from __future__ import annotations

from pathlib import Path

from grim.assets import RuntimeResources, load_runtime_resources, unload_runtime_resources
from grim.view import View


class RuntimeResourcesView:
    def __init__(self, view: View, *, assets_dir: Path) -> None:
        self._view = view
        self._assets_dir = Path(assets_dir)
        self._resources: RuntimeResources | None = None

    def open(self) -> None:
        self._resources = load_runtime_resources(self._assets_dir)
        try:
            self._view.open()
        except Exception:
            unload_runtime_resources(self._resources)
            self._resources = None
            raise

    def update(self, dt: float) -> None:
        self._view.update(dt)

    def draw(self) -> None:
        self._view.draw()

    def close(self) -> None:
        try:
            self._view.close()
        finally:
            unload_runtime_resources(self._resources)
            self._resources = None
