from __future__ import annotations

from dataclasses import dataclass, field
import io
from pathlib import Path

import pyray as rl
from PIL import Image

from . import jaz, paq


PAQ_NAME = "crimson.paq"


def find_paq_path(assets_root: Path, *, paq_name: str = PAQ_NAME) -> Path | None:
    """Return the first matching PAQ path for the given assets root.

    The repo layout often keeps extracted assets under `artifacts/assets/` while
    the runtime PAQ lives under `artifacts/runtime/`. Views typically point at
    the extracted root, so we look for common sibling/parent layouts too.
    """

    roots = (assets_root, assets_root.parent, assets_root.parent.parent)
    for root in roots:
        direct = root / paq_name
        if direct.is_file():
            return direct
        runtime = root / "runtime" / paq_name
        if runtime.is_file():
            return runtime
    return None


def resolve_asset_path(assets_root: Path, rel_path: str) -> Path | None:
    direct = assets_root / rel_path
    if direct.is_file():
        return direct
    legacy = assets_root / "crimson" / rel_path
    if legacy.is_file():
        return legacy
    return None


@dataclass(slots=True)
class TextureLoader:
    assets_root: Path
    cache: PaqTextureCache | None = None
    missing: list[str] = field(default_factory=list)
    _fs_textures: dict[str, rl.Texture] = field(default_factory=dict)

    @classmethod
    def from_assets_root(cls, assets_root: Path) -> TextureLoader:
        paq_path = find_paq_path(assets_root)
        if paq_path is not None:
            try:
                entries = load_paq_entries_from_path(paq_path)
                cache = PaqTextureCache(entries=entries, textures={})
                return cls(assets_root=assets_root, cache=cache)
            except Exception:
                pass
        return cls(assets_root=assets_root)

    def resolve_path(self, rel_path: str) -> Path | None:
        return resolve_asset_path(self.assets_root, rel_path)

    def _record_missing(self, rel_path: str) -> None:
        raise FileNotFoundError(f"Missing asset: {rel_path}")

    def load_from_cache(self, name: str, rel_path: str) -> rl.Texture | None:
        if self.cache is None:
            return None
        try:
            asset = self.cache.get_or_load(name, rel_path)
        except FileNotFoundError:
            return None
        if asset.texture is None:
            return None
        return asset.texture

    def load_from_path(self, name: str, rel_path: str) -> rl.Texture | None:
        if name in self._fs_textures:
            return self._fs_textures[name]
        path = resolve_asset_path(self.assets_root, rel_path)
        if path is None:
            self._record_missing(rel_path)
            return None
        texture = rl.load_texture(str(path))
        self._fs_textures[name] = texture
        return texture

    def get(self, *, name: str, paq_rel: str, fs_rel: str | None = None) -> rl.Texture | None:
        if self.cache is not None:
            texture = self.load_from_cache(name, paq_rel)
            if texture is not None:
                return texture
        if fs_rel is None:
            fs_rel = paq_rel
        return self.load_from_path(name, fs_rel)


@dataclass(slots=True)
class TextureAsset:
    name: str
    rel_path: str
    texture: rl.Texture2D | None

    def unload(self) -> None:
        texture = self.texture
        if texture is None:
            return
        rl.unload_texture(texture)
        self.texture = None


@dataclass(slots=True)
class LogoAssets:
    backplasma: TextureAsset
    mockup: TextureAsset
    logo_esrb: TextureAsset
    loading: TextureAsset
    cl_logo: TextureAsset

    def all(self) -> tuple[TextureAsset, ...]:
        return (
            self.backplasma,
            self.mockup,
            self.logo_esrb,
            self.loading,
            self.cl_logo,
        )

    def loaded_count(self) -> int:
        return sum(1 for asset in self.all() if asset.texture is not None)


@dataclass(slots=True)
class PaqTextureCache:
    entries: dict[str, bytes]
    textures: dict[str, TextureAsset]

    def get(self, name: str) -> TextureAsset | None:
        return self.textures.get(name)

    def texture(self, name: str) -> rl.Texture2D | None:
        asset = self.textures.get(name)
        return asset.texture if asset is not None else None

    def get_or_load(self, name: str, rel_path: str) -> TextureAsset:
        if name in self.textures:
            return self.textures[name]
        asset = _load_texture_asset_from_bytes(name, rel_path, self.entries.get(rel_path))
        self.textures[name] = asset
        return asset

    def loaded_count(self) -> int:
        return sum(1 for asset in self.textures.values() if asset.texture is not None)


def load_paq_entries_from_path(paq_path: Path) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    if not paq_path.exists():
        raise FileNotFoundError(f"Missing PAQ archive: {paq_path}")
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data
    return entries


def load_paq_entries(assets_dir: Path) -> dict[str, bytes]:
    return load_paq_entries_from_path(assets_dir / PAQ_NAME)


def _load_texture_from_bytes(data: bytes, fmt: str) -> rl.Texture2D:
    image = rl.load_image_from_memory(fmt, data, len(data))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
    return texture


def _load_texture_asset_from_bytes(name: str, rel_path: str, data: bytes | None) -> TextureAsset:
    if data is None:
        raise FileNotFoundError(f"Missing asset data: {rel_path}")
    if rel_path.lower().endswith(".jaz"):
        jaz_image = jaz.decode_jaz_bytes(data)
        buf = io.BytesIO()
        jaz_image.composite_image().save(buf, format="PNG")
        return TextureAsset(
            name=name,
            rel_path=rel_path,
            texture=_load_texture_from_bytes(buf.getvalue(), ".png"),
        )
    if rel_path.lower().endswith(".tga"):
        img = Image.open(io.BytesIO(data))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return TextureAsset(
            name=name,
            rel_path=rel_path,
            texture=_load_texture_from_bytes(buf.getvalue(), ".png"),
        )
    if rel_path.lower().endswith((".jpg", ".jpeg")):
        img = Image.open(io.BytesIO(data))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return TextureAsset(
            name=name,
            rel_path=rel_path,
            texture=_load_texture_from_bytes(buf.getvalue(), ".png"),
        )
    return TextureAsset(name=name, rel_path=rel_path, texture=None)


def load_logo_assets(assets_dir: Path, *, entries: dict[str, bytes] | None = None) -> LogoAssets:
    if entries is None:
        entries = load_paq_entries(assets_dir)
    return LogoAssets(
        backplasma=_load_texture_asset_from_bytes(
            "backplasma", "load/backplasma.jaz", entries.get("load/backplasma.jaz")
        ),
        mockup=_load_texture_asset_from_bytes("mockup", "load/mockup.jaz", entries.get("load/mockup.jaz")),
        logo_esrb=_load_texture_asset_from_bytes(
            "logo_esrb", "load/esrb_mature.jaz", entries.get("load/esrb_mature.jaz")
        ),
        loading=_load_texture_asset_from_bytes("loading", "load/loading.jaz", entries.get("load/loading.jaz")),
        cl_logo=_load_texture_asset_from_bytes(
            "cl_logo",
            "load/logo_crimsonland.tga",
            entries.get("load/logo_crimsonland.tga"),
        ),
    )
