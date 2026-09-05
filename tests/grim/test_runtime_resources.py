from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from grim import assets


@pytest.mark.parametrize("failure", ["decode", "settings", "font"])
def test_partial_resource_load_releases_every_created_texture(mocker, tmp_path: Path, failure: str) -> None:
    specs = {
        assets.TextureId.SMALL_WHITE: assets.TextureSpec("font.tga"),
        assets.TextureId.TROOPER: assets.TextureSpec("trooper.tga"),
    }
    mocker.patch.object(assets, "TEXTURE_SPECS", specs)
    mocker.patch.object(assets, "load_paq_entries", return_value={"load/smallFnt.dat": bytes(256)})
    mocker.patch.object(assets, "_select_texture_asset", side_effect=lambda entries, name: (name, b"image"))
    textures = [SimpleNamespace(id=1), SimpleNamespace(id=2)]
    upload = mocker.patch.object(assets, "_load_texture_asset_from_bytes", side_effect=textures)
    settings = mocker.patch.object(assets, "_apply_texture_settings")
    unload = mocker.patch.object(assets.rl, "unload_texture")
    if failure == "decode":
        upload.side_effect = [textures[0], ValueError("bad image")]
        expected = textures[:1]
    elif failure == "settings":
        settings.side_effect = [None, ValueError("bad settings")]
        expected = textures
    else:
        mocker.patch.object(assets, "_build_small_font", side_effect=ValueError("bad font"))
        expected = textures
    with pytest.raises(ValueError):
        assets.load_runtime_resources(tmp_path)
    assert [call.args[0] for call in unload.call_args_list] == list(reversed(expected))


@pytest.mark.parametrize("widths", [None, b"", bytes(255), bytes(257)])
def test_invalid_font_widths_fail_before_gpu_allocation(mocker, tmp_path: Path, widths: bytes | None) -> None:
    entries = {} if widths is None else {"load/smallFnt.dat": widths}
    mocker.patch.object(assets, "load_paq_entries", return_value=entries)
    upload = mocker.patch.object(assets, "_load_texture_asset_from_bytes")
    with pytest.raises((ValueError, FileNotFoundError)):
        assets.load_runtime_resources(tmp_path)
    upload.assert_not_called()


def test_failed_gpu_upload_releases_cpu_image(mocker) -> None:
    image = object()
    mocker.patch.object(assets.rl, "load_image_from_memory", return_value=image)
    mocker.patch.object(assets.rl, "load_texture_from_image", side_effect=RuntimeError("upload failed"))
    unload = mocker.patch.object(assets.rl, "unload_image")
    with pytest.raises(RuntimeError, match="upload failed"):
        assets._load_texture_from_bytes(b"image", ".png")
    unload.assert_called_once_with(image)


def test_failed_initial_texture_settings_release_texture(mocker) -> None:
    texture = SimpleNamespace(id=1)
    mocker.patch.object(assets.rl, "load_image_from_memory", return_value=object())
    mocker.patch.object(assets.rl, "load_texture_from_image", return_value=texture)
    mocker.patch.object(assets.rl, "unload_image")
    mocker.patch.object(assets.rl, "set_texture_filter", side_effect=RuntimeError("filter failed"))
    unload = mocker.patch.object(assets.rl, "unload_texture")
    with pytest.raises(RuntimeError, match="filter failed"):
        assets._load_texture_from_bytes(b"image", ".png")
    unload.assert_called_once_with(texture)
