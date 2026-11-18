from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

from grim import assets


@pytest.mark.parametrize("failure", ["decode", "font"])
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
    unload = mocker.patch.object(assets.rl, "unload_texture")
    if failure == "decode":
        upload.side_effect = [textures[0], ValueError("bad image")]
        expected = textures[:1]
    else:
        mocker.patch.object(assets, "_build_small_font", side_effect=ValueError("bad font"))
        expected = textures
    with pytest.raises(ValueError):
        assets.load_runtime_resources(tmp_path)
    assert [call.args[0] for call in unload.call_args_list] == list(reversed(expected))


@pytest.mark.parametrize("widths", [None, bytes(255)])
def test_invalid_font_widths_fail_before_gpu_allocation(mocker, tmp_path: Path, widths: bytes | None) -> None:
    entries = {} if widths is None else {"load/smallFnt.dat": widths}
    mocker.patch.object(assets, "load_paq_entries", return_value=entries)
    upload = mocker.patch.object(assets, "_load_texture_asset_from_bytes")
    with pytest.raises((ValueError, FileNotFoundError)):
        assets.load_runtime_resources(tmp_path)
    upload.assert_not_called()


@pytest.mark.parametrize("mode", ["L", "LA", "RGB", "RGBA", "P"])
def test_texture_upload_preserves_pixels(mocker, mode):
    image = Image.new("RGBA", (2, 1))
    image.putpixel((0, 0), (23, 45, 67, 89))
    image.putpixel((1, 0), (12, 34, 56, 78))
    image = image.convert(mode)
    expected = image.convert("RGBA") if mode == "P" else image

    def capture(upload):
        assert (upload.width, upload.height) == image.size
        actual = bytes(assets.rl.ffi.buffer(upload.data, len(expected.tobytes())))
        assert actual == expected.tobytes()
        return SimpleNamespace(id=1)

    mocker.patch.object(assets.rl, "load_texture_from_image", side_effect=capture)
    mocker.patch.object(assets.rl, "set_texture_filter")
    unload = mocker.patch.object(assets.rl, "unload_image")
    assets.upload_texture(image)
    unload.assert_not_called()


@pytest.mark.parametrize("setting", ["set_texture_filter", "set_texture_wrap"])
def test_failed_initial_texture_settings_release_texture(mocker, setting) -> None:
    texture = SimpleNamespace(id=1)
    mocker.patch.object(assets.rl, "load_texture_from_image", return_value=texture)
    mocker.patch.object(assets.rl, "set_texture_filter")
    mocker.patch.object(assets.rl, setting, side_effect=RuntimeError("settings failed"))
    unload = mocker.patch.object(assets.rl, "unload_texture")
    with pytest.raises(RuntimeError, match="settings failed"):
        assets.upload_texture(Image.new("RGB", (1, 1)), clamp=True)
    unload.assert_called_once_with(texture)
