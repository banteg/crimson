from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path

import pyray as rl
from PIL import Image

from . import jaz


ASSET_ROOT_NAME = "crimson"


@dataclass(slots=True)
class TextureAsset:
    name: str
    rel_path: str
    texture: rl.Texture2D | None

    def unload(self) -> None:
        if self.texture is not None:
            rl.unload_texture(self.texture)


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

    def unload(self) -> None:
        for asset in self.all():
            asset.unload()


def _resolve_asset_path(assets_dir: Path, rel_path: str) -> tuple[Path, Path | None]:
    raw_path = assets_dir / ASSET_ROOT_NAME / Path(rel_path)
    suffix = raw_path.suffix.lower()
    if suffix in (".jaz", ".tga"):
        return raw_path.with_suffix(".png"), raw_path
    return raw_path, None


def _load_texture_from_bytes(data: bytes, fmt: str) -> rl.Texture2D:
    image = rl.load_image_from_memory(fmt, data, len(data))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    return texture


def _load_texture_asset(assets_dir: Path, name: str, rel_path: str) -> TextureAsset:
    png_path, raw_path = _resolve_asset_path(assets_dir, rel_path)
    if png_path.exists():
        return TextureAsset(name=name, rel_path=rel_path, texture=rl.load_texture(str(png_path)))
    if raw_path is None or not raw_path.exists():
        return TextureAsset(name=name, rel_path=rel_path, texture=None)
    if raw_path.suffix.lower() == ".jaz":
        jaz_image = jaz.decode_jaz_bytes(raw_path.read_bytes())
        buf = io.BytesIO()
        jaz_image.composite_image().save(buf, format="PNG")
        return TextureAsset(
            name=name,
            rel_path=rel_path,
            texture=_load_texture_from_bytes(buf.getvalue(), ".png"),
        )
    if raw_path.suffix.lower() == ".tga":
        img = Image.open(raw_path)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return TextureAsset(
            name=name,
            rel_path=rel_path,
            texture=_load_texture_from_bytes(buf.getvalue(), ".png"),
        )
    return TextureAsset(name=name, rel_path=rel_path, texture=None)


def load_logo_assets(assets_dir: Path) -> LogoAssets:
    return LogoAssets(
        backplasma=_load_texture_asset(assets_dir, "backplasma", "load/backplasma.jaz"),
        mockup=_load_texture_asset(assets_dir, "mockup", "load/mockup.jaz"),
        logo_esrb=_load_texture_asset(assets_dir, "logo_esrb", "load/esrb_mature.jaz"),
        loading=_load_texture_asset(assets_dir, "loading", "load/loading.jaz"),
        cl_logo=_load_texture_asset(
            assets_dir, "cl_logo", "load/logo_crimsonland.tga"
        ),
    )
