from __future__ import annotations

import io
import urllib.request
from pathlib import Path
from typing import cast

import pytest

from crimson.assets_fetch import _download_file, download_missing_paqs
from grim.console import ConsoleLog, ConsoleState
from grim.paq import build_entries


class _FakeResponse(io.BytesIO):
    pass


def test_download_file_uses_unique_tempfile(mocker, tmp_path: Path) -> None:
    payload = build_entries([("example.txt", b"payload")])

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


def test_stale_non_paq_response_does_not_prevent_retry(mocker, tmp_path: Path) -> None:
    valid_paq = build_entries([("example.txt", b"payload")])
    urlopen = mocker.patch.object(
        urllib.request,
        "urlopen",
        side_effect=[_FakeResponse(b"<html>temporary CDN error</html>"), _FakeResponse(valid_paq)],
    )
    console = ConsoleState(base_dir=tmp_path, log=ConsoleLog(base_dir=tmp_path))

    first = download_missing_paqs(tmp_path, console, names=("crimson.paq",))
    assert len(first) == 1 and not first[0].ok
    assert not (tmp_path / "crimson.paq").exists()

    second = download_missing_paqs(tmp_path, console, names=("crimson.paq",))
    assert len(second) == 1 and second[0].ok
    assert (tmp_path / "crimson.paq").read_bytes() == valid_paq
    assert urlopen.call_count == 2


@pytest.mark.parametrize("payload", [b"", b"paq", b"<html>temporary CDN error</html>"])
def test_invalid_download_preserves_existing_archive(mocker, tmp_path: Path, payload: bytes) -> None:
    existing = build_entries([("existing.txt", b"keep")])
    dest = tmp_path / "crimson.paq"
    dest.write_bytes(existing)
    mocker.patch.object(urllib.request, "urlopen", return_value=_FakeResponse(payload))

    with pytest.raises(ValueError, match="Invalid PAQ archive"):
        _download_file("http://example.invalid/crimson.paq", dest)

    assert dest.read_bytes() == existing
    assert not list(tmp_path.glob("crimson.paq.*.tmp"))
