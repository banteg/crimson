from __future__ import annotations

import pytest

from crimson_re import match, match_builds, match_freeware_sizes


def test_editor_offset_extent_requires_the_declaring_tu_and_release() -> None:
    source = "decomp/1.4/crimson/crimson/game/game_frame_update.cpp"
    name = "_?offset@?CF@??game_frame_update@frame_update140@@YAEXZ@4Ueditor_point@2@A"
    assert match_freeware_sizes.declared_size("1.3.0", source, name) == 8
    assert match_freeware_sizes.declared_size("1.4.0", source, name) is None
    assert match_freeware_sizes.declared_size("1.3.0", "other.cpp", name) is None


def test_vc6_rejects_an_incorrect_perk_table_extent(monkeypatch: pytest.MonkeyPatch) -> None:
    version = "1.0.2"
    image = match_builds.load_registry().image(version, "crimson.exe")
    scratch = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/perk_meta_table_init")
    if not image.path.is_file() or not match._compiler_executable_path(scratch, match.DEFAULT_MATCH_ROOT).is_file():
        pytest.skip("original 1.0.2 image and VC6 compiler required")
    config = image.scratch_config(scratch)
    symbol = "?perk_meta_table@@3PAVperk_meta_cpp_t@@A"
    match_freeware_sizes.verify_declared_sizes(version, config, [symbol])
    monkeypatch.setitem(match_freeware_sizes._PERK_SIZES, version, 513)
    with pytest.raises(ValueError, match="VC6 sizeof check failed"):
        match_freeware_sizes.verify_declared_sizes(version, config, [symbol])
