from __future__ import annotations

from pathlib import Path

from grim.assets import load_runtime_resources, runtime_resources_for, unload_runtime_resources


class RuntimeResourcesDebugViewMixin:
    _assets_root: Path
    _runtime_resources_owned = False

    def _open_runtime_resources(self) -> None:
        try:
            runtime_resources_for(self._assets_root)
        except RuntimeError:
            load_runtime_resources(self._assets_root)
            self._runtime_resources_owned = True
        else:
            self._runtime_resources_owned = False

    def _close_runtime_resources(self) -> None:
        if self._runtime_resources_owned:
            try:
                resources = runtime_resources_for(self._assets_root)
            except RuntimeError:
                pass
            else:
                unload_runtime_resources(resources)
        self._runtime_resources_owned = False
