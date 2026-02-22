from __future__ import annotations

from pathlib import Path
from typing import cast

from crimson.views.beam_debug import BeamDebugView, resolve_beam_debug_assets_root
from grim.assets import TextureLoader
from grim.view import ViewContext


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")


def test_resolve_beam_debug_assets_root_prefers_explicit_assets(tmp_path: Path, monkeypatch) -> None:
    preferred = tmp_path / "preferred-assets"
    _touch(preferred / "game" / "projs.jaz")
    _touch(preferred / "game" / "particles.jaz")

    runtime_dir = tmp_path / "deep" / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    (runtime_dir / "crimson.paq").write_bytes(b"paq")
    monkeypatch.setenv("CRIMSON_RUNTIME_DIR", str(runtime_dir))

    resolved = resolve_beam_debug_assets_root(preferred)
    assert resolved == preferred.resolve(strict=False)


def test_resolve_beam_debug_assets_root_falls_back_to_runtime(tmp_path: Path, monkeypatch) -> None:
    preferred = tmp_path / "nested" / "preferred-assets"
    preferred.mkdir(parents=True, exist_ok=True)

    runtime_dir = tmp_path / "deep" / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    (runtime_dir / "crimson.paq").write_bytes(b"paq")
    monkeypatch.setenv("CRIMSON_RUNTIME_DIR", str(runtime_dir))

    resolved = resolve_beam_debug_assets_root(preferred)
    assert resolved == runtime_dir.resolve(strict=False)


def test_missing_optional_texture_is_recorded_without_exception() -> None:
    class _MissingLoader:
        def get(self, *, name: str, paq_rel: str):
            raise FileNotFoundError(paq_rel)

    view = BeamDebugView(ViewContext(assets_dir=Path("artifacts") / "assets"))
    view._texture_loader = cast(TextureLoader, _MissingLoader())

    loaded = view._load_optional_texture(name="projs", cache_path="game/projs.jaz")
    assert loaded is None
    assert "game/projs.jaz" in view._missing_assets
