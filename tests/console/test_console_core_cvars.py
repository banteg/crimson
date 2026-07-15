from __future__ import annotations

from grim.console import create_console, register_core_cvars


def test_core_cvars_include_native_terrain_filter_default(tmp_path) -> None:
    console = create_console(tmp_path)

    register_core_cvars(console, width=1024, height=768)

    terrain_filter = console.cvars["cv_terrainFilter"]
    assert terrain_filter.value == "1"
    assert terrain_filter.value_f == 1.0
