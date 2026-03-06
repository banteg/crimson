from __future__ import annotations

import io
import urllib.request
from pathlib import Path
from typing import cast

from crimson.assets_fetch import _download_file


class _FakeResponse(io.BytesIO):
    pass


def test_download_file_uses_unique_tempfile(mocker, tmp_path: Path) -> None:
    payload = b"paq payload\n" * 128

    def fake_urlopen(req: object, *, timeout: int) -> _FakeResponse:
        return _FakeResponse(payload)

    mocker.patch.object(urllib.request, "urlopen", side_effect=fake_urlopen)

    original_replace = Path.replace

    def spy_replace(self: Path, target: Path) -> Path:
        return original_replace(self, target)

    replace = mocker.patch.object(Path, "replace", autospec=True, side_effect=spy_replace)

    dest = tmp_path / "crimson.paq"
    _download_file("http://example.invalid/crimson.paq", dest)

    assert dest.read_bytes() == payload
    replace.assert_called_once()
    tmp_source = cast("Path", replace.call_args.args[0])
    assert tmp_source.parent == dest.parent
    assert tmp_source != dest.with_suffix(dest.suffix + ".tmp")
