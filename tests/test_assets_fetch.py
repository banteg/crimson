from __future__ import annotations

import io
from pathlib import Path
import urllib.request

from crimson.assets_fetch import _download_file


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


def test_download_file_uses_unique_tempfile(monkeypatch: object, tmp_path: Path) -> None:
    payload = b"paq payload\n" * 128

    def fake_urlopen(req: object, *, timeout: int) -> _FakeResponse:
        return _FakeResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    replaced: list[Path] = []
    original_replace = Path.replace

    def spy_replace(self: Path, target: Path) -> Path:
        replaced.append(self)
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", spy_replace)

    dest = tmp_path / "crimson.paq"
    _download_file("http://example.invalid/crimson.paq", dest)

    assert dest.read_bytes() == payload
    assert replaced
    assert replaced[0].parent == dest.parent
    assert replaced[0] != dest.with_suffix(dest.suffix + ".tmp")

