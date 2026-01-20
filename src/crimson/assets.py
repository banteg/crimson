from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path

import pyray as rl
from PIL import Image

from . import jaz, paq


PAQ_NAME = "crimson.paq"


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


def _load_texture_from_bytes(data: bytes, fmt: str) -> rl.Texture2D:
    image = rl.load_image_from_memory(fmt, data, len(data))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    return texture


def _load_texture_asset_from_bytes(
    name: str, rel_path: str, data: bytes | None
) -> TextureAsset:
    if data is None:
        return TextureAsset(name=name, rel_path=rel_path, texture=None)
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
    return TextureAsset(name=name, rel_path=rel_path, texture=None)


def load_logo_assets(assets_dir: Path) -> LogoAssets:
    paq_path = assets_dir / PAQ_NAME
    entries: dict[str, bytes] = {}
    if paq_path.exists():
        for name, data in paq.iter_entries(paq_path):
            entries[name.replace("\\", "/")] = data
    return LogoAssets(
        backplasma=_load_texture_asset_from_bytes(
            "backplasma", "load/backplasma.jaz", entries.get("load/backplasma.jaz")
        ),
        mockup=_load_texture_asset_from_bytes(
            "mockup", "load/mockup.jaz", entries.get("load/mockup.jaz")
        ),
        logo_esrb=_load_texture_asset_from_bytes(
            "logo_esrb", "load/esrb_mature.jaz", entries.get("load/esrb_mature.jaz")
        ),
        loading=_load_texture_asset_from_bytes(
            "loading", "load/loading.jaz", entries.get("load/loading.jaz")
        ),
        cl_logo=_load_texture_asset_from_bytes(
            "cl_logo", "load/logo_crimsonland.tga", entries.get("load/logo_crimsonland.tga")
        ),
    )
