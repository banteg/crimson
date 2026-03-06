from __future__ import annotations

import io
from enum import Enum, auto
from pathlib import Path
from typing import Final, cast

import msgspec
from PIL import Image

from grim.raylib_api import rl

from . import jaz, paq

PAQ_NAME = "crimson.paq"


class TextureId(Enum):
    BACKPLASMA = auto()
    MOCKUP = auto()
    LOGO_ESRB = auto()
    LOADING = auto()
    CL_LOGO = auto()
    SPLASH_10TONS = auto()
    SPLASH_REFLEXIVE = auto()
    DEFAULT_FONT_COURIER = auto()
    SMALL_WHITE = auto()
    TROOPER = auto()
    ZOMBIE = auto()
    SPIDER_SP1 = auto()
    SPIDER_SP2 = auto()
    ALIEN = auto()
    LIZARD = auto()
    ARROW = auto()
    BULLET_I = auto()
    BULLET_TRAIL = auto()
    BODYSET = auto()
    PROJS = auto()
    UI_ICON_AIM = auto()
    UI_BUTTON_SM = auto()
    UI_BUTTON_MD = auto()
    UI_CHECK_ON = auto()
    UI_CHECK_OFF = auto()
    UI_RECT_OFF = auto()
    UI_RECT_ON = auto()
    BONUSES = auto()
    UI_IND_BULLET = auto()
    UI_IND_ROCKET = auto()
    UI_IND_ELECTRIC = auto()
    UI_IND_FIRE = auto()
    PARTICLES = auto()
    UI_IND_LIFE = auto()
    UI_IND_PANEL = auto()
    UI_ARROW = auto()
    UI_CURSOR = auto()
    UI_AIM = auto()
    TER_Q1_BASE = auto()
    TER_Q1_OVERLAY = auto()
    TER_Q2_BASE = auto()
    TER_Q2_OVERLAY = auto()
    TER_Q3_BASE = auto()
    TER_Q3_OVERLAY = auto()
    TER_Q4_BASE = auto()
    TER_Q4_OVERLAY = auto()
    UI_TEXT_LEVEL_COMPLETE = auto()
    UI_TEXT_QUEST = auto()
    UI_NUM1 = auto()
    UI_NUM2 = auto()
    UI_NUM3 = auto()
    UI_NUM4 = auto()
    UI_NUM5 = auto()
    UI_WICONS = auto()
    UI_GAME_TOP = auto()
    UI_LIFE_HEART = auto()
    UI_CLOCK_TABLE = auto()
    UI_CLOCK_POINTER = auto()
    MUZZLE_FLASH = auto()
    UI_DROP_ON = auto()
    UI_DROP_OFF = auto()
    UI_SIGN_CRIMSON = auto()
    UI_MENU_ITEM = auto()
    UI_MENU_PANEL = auto()
    UI_ITEM_TEXTS = auto()
    UI_TEXT_REAPER = auto()
    UI_TEXT_WELL_DONE = auto()
    UI_TEXT_CONTROLS = auto()
    UI_TEXT_PICK_A_PERK = auto()
    UI_TEXT_LEVEL_UP = auto()


class TextureSpec(msgspec.Struct, frozen=True):
    legacy_name: str
    rel_path: str
    clamp: bool = False
    point_filter: bool = False


TEXTURE_SPECS: Final[dict[TextureId, TextureSpec]] = {
    TextureId.BACKPLASMA: TextureSpec("backplasma", "load/backplasma.jaz"),
    TextureId.MOCKUP: TextureSpec("mockup", "load/mockup.jaz"),
    TextureId.LOGO_ESRB: TextureSpec("logo_esrb", "load/esrb_mature.jaz"),
    TextureId.LOADING: TextureSpec("loading", "load/loading.jaz"),
    TextureId.CL_LOGO: TextureSpec("cl_logo", "load/logo_crimsonland.tga"),
    TextureId.SPLASH_10TONS: TextureSpec("splash10tons", "load/splash10tons.jaz"),
    TextureId.SPLASH_REFLEXIVE: TextureSpec("splashReflexive", "load/splashReflexive.jpg"),
    TextureId.DEFAULT_FONT_COURIER: TextureSpec("default_font_courier", "load/default_font_courier.tga"),
    TextureId.SMALL_WHITE: TextureSpec("smallWhite", "load/smallWhite.tga", point_filter=True),
    TextureId.TROOPER: TextureSpec("trooper", "game/trooper.jaz"),
    TextureId.ZOMBIE: TextureSpec("zombie", "game/zombie.jaz"),
    TextureId.SPIDER_SP1: TextureSpec("spider_sp1", "game/spider_sp1.jaz"),
    TextureId.SPIDER_SP2: TextureSpec("spider_sp2", "game/spider_sp2.jaz"),
    TextureId.ALIEN: TextureSpec("alien", "game/alien.jaz"),
    TextureId.LIZARD: TextureSpec("lizard", "game/lizard.jaz"),
    TextureId.ARROW: TextureSpec("arrow", "load/arrow.tga"),
    TextureId.BULLET_I: TextureSpec("bullet_i", "load/bullet16.tga"),
    TextureId.BULLET_TRAIL: TextureSpec("bulletTrail", "load/bulletTrail.tga"),
    TextureId.BODYSET: TextureSpec("bodyset", "game/bodyset.jaz"),
    TextureId.PROJS: TextureSpec("projs", "game/projs.jaz"),
    TextureId.UI_ICON_AIM: TextureSpec("ui_iconAim", "ui/ui_iconAim.jaz", clamp=True),
    TextureId.UI_BUTTON_SM: TextureSpec("ui_buttonSm", "ui/ui_button_64x32.jaz", clamp=True),
    TextureId.UI_BUTTON_MD: TextureSpec("ui_buttonMd", "ui/ui_button_128x32.jaz", clamp=True),
    TextureId.UI_CHECK_ON: TextureSpec("ui_checkOn", "ui/ui_checkOn.jaz", clamp=True),
    TextureId.UI_CHECK_OFF: TextureSpec("ui_checkOff", "ui/ui_checkOff.jaz", clamp=True),
    TextureId.UI_RECT_OFF: TextureSpec("ui_rectOff", "ui/ui_rectOff.jaz", clamp=True),
    TextureId.UI_RECT_ON: TextureSpec("ui_rectOn", "ui/ui_rectOn.jaz", clamp=True),
    TextureId.BONUSES: TextureSpec("bonuses", "game/bonuses.jaz"),
    TextureId.UI_IND_BULLET: TextureSpec("ui_indBullet", "ui/ui_indBullet.jaz", clamp=True),
    TextureId.UI_IND_ROCKET: TextureSpec("ui_indRocket", "ui/ui_indRocket.jaz", clamp=True),
    TextureId.UI_IND_ELECTRIC: TextureSpec("ui_indElectric", "ui/ui_indElectric.jaz", clamp=True),
    TextureId.UI_IND_FIRE: TextureSpec("ui_indFire", "ui/ui_indFire.jaz", clamp=True),
    TextureId.PARTICLES: TextureSpec("particles", "game/particles.jaz"),
    TextureId.UI_IND_LIFE: TextureSpec("ui_indLife", "ui/ui_indLife.jaz", clamp=True),
    TextureId.UI_IND_PANEL: TextureSpec("ui_indPanel", "ui/ui_indPanel.jaz", clamp=True),
    TextureId.UI_ARROW: TextureSpec("ui_arrow", "ui/ui_arrow.jaz", clamp=True),
    TextureId.UI_CURSOR: TextureSpec("ui_cursor", "ui/ui_cursor.jaz", clamp=True),
    TextureId.UI_AIM: TextureSpec("ui_aim", "ui/ui_aim.jaz", clamp=True),
    TextureId.TER_Q1_BASE: TextureSpec("ter_q1_base", "ter/ter_q1_base.jaz"),
    TextureId.TER_Q1_OVERLAY: TextureSpec("ter_q1_tex1", "ter/ter_q1_tex1.jaz"),
    TextureId.TER_Q2_BASE: TextureSpec("ter_q2_base", "ter/ter_q2_base.jaz"),
    TextureId.TER_Q2_OVERLAY: TextureSpec("ter_q2_tex1", "ter/ter_q2_tex1.jaz"),
    TextureId.TER_Q3_BASE: TextureSpec("ter_q3_base", "ter/ter_q3_base.jaz"),
    TextureId.TER_Q3_OVERLAY: TextureSpec("ter_q3_tex1", "ter/ter_q3_tex1.jaz"),
    TextureId.TER_Q4_BASE: TextureSpec("ter_q4_base", "ter/ter_q4_base.jaz"),
    TextureId.TER_Q4_OVERLAY: TextureSpec("ter_q4_tex1", "ter/ter_q4_tex1.jaz"),
    TextureId.UI_TEXT_LEVEL_COMPLETE: TextureSpec("ui_textLevComp", "ui/ui_textLevComp.jaz", clamp=True),
    TextureId.UI_TEXT_QUEST: TextureSpec("ui_textQuest", "ui/ui_textQuest.jaz", clamp=True),
    TextureId.UI_NUM1: TextureSpec("ui_num1", "ui/ui_num1.jaz", clamp=True),
    TextureId.UI_NUM2: TextureSpec("ui_num2", "ui/ui_num2.jaz", clamp=True),
    TextureId.UI_NUM3: TextureSpec("ui_num3", "ui/ui_num3.jaz", clamp=True),
    TextureId.UI_NUM4: TextureSpec("ui_num4", "ui/ui_num4.jaz", clamp=True),
    TextureId.UI_NUM5: TextureSpec("ui_num5", "ui/ui_num5.jaz", clamp=True),
    TextureId.UI_WICONS: TextureSpec("ui_wicons", "ui/ui_wicons.jaz", clamp=True),
    TextureId.UI_GAME_TOP: TextureSpec("iGameUI", "ui/ui_gameTop.jaz", clamp=True),
    TextureId.UI_LIFE_HEART: TextureSpec("iHeart", "ui/ui_lifeHeart.jaz", clamp=True),
    TextureId.UI_CLOCK_TABLE: TextureSpec("ui_clockTable", "ui/ui_clockTable.jaz", clamp=True),
    TextureId.UI_CLOCK_POINTER: TextureSpec("ui_clockPointer", "ui/ui_clockPointer.jaz", clamp=True),
    TextureId.MUZZLE_FLASH: TextureSpec("muzzleFlash", "game/muzzleFlash.jaz"),
    TextureId.UI_DROP_ON: TextureSpec("ui_dropOn", "ui/ui_dropDownOn.jaz", clamp=True),
    TextureId.UI_DROP_OFF: TextureSpec("ui_dropOff", "ui/ui_dropDownOff.jaz", clamp=True),
    TextureId.UI_SIGN_CRIMSON: TextureSpec("ui_signCrimson", "ui/ui_signCrimson.jaz", clamp=True),
    TextureId.UI_MENU_ITEM: TextureSpec("ui_menuItem", "ui/ui_menuItem.jaz", clamp=True),
    TextureId.UI_MENU_PANEL: TextureSpec("ui_menuPanel", "ui/ui_menuPanel.jaz", clamp=True),
    TextureId.UI_ITEM_TEXTS: TextureSpec("ui_itemTexts", "ui/ui_itemTexts.jaz", clamp=True),
    TextureId.UI_TEXT_REAPER: TextureSpec("ui_textReaper", "ui/ui_textReaper.jaz", clamp=True),
    TextureId.UI_TEXT_WELL_DONE: TextureSpec("ui_textWellDone", "ui/ui_textWellDone.jaz", clamp=True),
    TextureId.UI_TEXT_CONTROLS: TextureSpec("ui_textControls", "ui/ui_textControls.jaz", clamp=True),
    TextureId.UI_TEXT_PICK_A_PERK: TextureSpec("ui_textPickAPerk", "ui/ui_textPickAPerk.jaz", clamp=True),
    TextureId.UI_TEXT_LEVEL_UP: TextureSpec("ui_textLevelUp", "ui/ui_textLevelUp.jaz", clamp=True),
}

class TextureAsset(msgspec.Struct):
    name: str
    rel_path: str
    texture: rl.Texture | None

    def unload(self) -> None:
        texture = self.texture
        if texture is None:
            return
        rl.unload_texture(texture)
        self.texture = None


class LogoAssets(msgspec.Struct):
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


class RuntimeResources(msgspec.Struct):
    assets_dir: Path
    textures: dict[TextureId, rl.Texture]
    logos: LogoAssets
    small_font_widths: list[int]

    def texture(self, texture_id: TextureId) -> rl.Texture | None:
        return self.textures.get(texture_id)

    def unload(self) -> None:
        seen: set[int] = set()
        for texture in self.textures.values():
            texture_id = int(texture.id)
            if texture_id <= 0 or texture_id in seen:
                continue
            rl.unload_texture(texture)
            seen.add(texture_id)
        self.textures.clear()


_REGISTERED_RESOURCES: dict[Path, RuntimeResources] = {}


def _normalize_assets_dir(assets_dir: Path) -> Path:
    return Path(assets_dir).resolve()


def register_runtime_resources(resources: RuntimeResources) -> None:
    _REGISTERED_RESOURCES[_normalize_assets_dir(resources.assets_dir)] = resources


def unregister_runtime_resources(assets_dir: Path) -> None:
    _REGISTERED_RESOURCES.pop(_normalize_assets_dir(assets_dir), None)


def runtime_resources_for(assets_dir: Path) -> RuntimeResources:
    normalized = _normalize_assets_dir(assets_dir)
    resources = _REGISTERED_RESOURCES.get(normalized)
    if resources is None:
        raise RuntimeError(f"runtime resources not loaded for {assets_dir}")
    return resources


def texture_for(assets_dir: Path, texture_id: TextureId) -> rl.Texture | None:
    return runtime_resources_for(assets_dir).texture(texture_id)


def load_paq_entries_from_path(paq_path: Path) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    if not paq_path.exists():
        raise FileNotFoundError(f"Missing PAQ archive: {paq_path}")
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data
    return entries


def load_paq_entries(assets_dir: Path) -> dict[str, bytes]:
    return load_paq_entries_from_path(Path(assets_dir) / PAQ_NAME)


def _load_texture_from_bytes(data: bytes, fmt: str) -> rl.Texture:
    image = rl.load_image_from_memory(fmt, cast(str, data), len(data))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
    return texture


def _apply_texture_settings(texture: rl.Texture, *, clamp: bool, point_filter: bool) -> None:
    if clamp:
        rl.set_texture_wrap(texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
    if point_filter:
        rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_POINT)


def _load_texture_asset_from_bytes(name: str, rel_path: str, data: bytes | None) -> TextureAsset:
    if data is None:
        raise FileNotFoundError(f"Missing asset data: {rel_path}")
    texture: rl.Texture | None
    if rel_path.lower().endswith(".jaz"):
        jaz_image = jaz.decode_jaz_bytes(data)
        buf = io.BytesIO()
        jaz_image.composite_image().save(buf, format="PNG")
        texture = _load_texture_from_bytes(buf.getvalue(), ".png")
    elif rel_path.lower().endswith(".tga"):
        img = Image.open(io.BytesIO(data))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        texture = _load_texture_from_bytes(buf.getvalue(), ".png")
    elif rel_path.lower().endswith((".jpg", ".jpeg")):
        img = Image.open(io.BytesIO(data))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        texture = _load_texture_from_bytes(buf.getvalue(), ".png")
    else:
        texture = None
    return TextureAsset(name=name, rel_path=rel_path, texture=texture)


def _build_logo_assets(textures: dict[TextureId, rl.Texture]) -> LogoAssets:
    return LogoAssets(
        backplasma=TextureAsset(
            name=TEXTURE_SPECS[TextureId.BACKPLASMA].legacy_name,
            rel_path=TEXTURE_SPECS[TextureId.BACKPLASMA].rel_path,
            texture=textures.get(TextureId.BACKPLASMA),
        ),
        mockup=TextureAsset(
            name=TEXTURE_SPECS[TextureId.MOCKUP].legacy_name,
            rel_path=TEXTURE_SPECS[TextureId.MOCKUP].rel_path,
            texture=textures.get(TextureId.MOCKUP),
        ),
        logo_esrb=TextureAsset(
            name=TEXTURE_SPECS[TextureId.LOGO_ESRB].legacy_name,
            rel_path=TEXTURE_SPECS[TextureId.LOGO_ESRB].rel_path,
            texture=textures.get(TextureId.LOGO_ESRB),
        ),
        loading=TextureAsset(
            name=TEXTURE_SPECS[TextureId.LOADING].legacy_name,
            rel_path=TEXTURE_SPECS[TextureId.LOADING].rel_path,
            texture=textures.get(TextureId.LOADING),
        ),
        cl_logo=TextureAsset(
            name=TEXTURE_SPECS[TextureId.CL_LOGO].legacy_name,
            rel_path=TEXTURE_SPECS[TextureId.CL_LOGO].rel_path,
            texture=textures.get(TextureId.CL_LOGO),
        ),
    )


def load_runtime_resources(assets_dir: Path) -> RuntimeResources:
    entries = load_paq_entries(Path(assets_dir))
    textures: dict[TextureId, rl.Texture] = {}
    for texture_id, spec in TEXTURE_SPECS.items():
        asset = _load_texture_asset_from_bytes(spec.legacy_name, spec.rel_path, entries.get(spec.rel_path))
        texture = asset.texture
        if texture is None:
            raise FileNotFoundError(f"Missing runtime texture: {spec.rel_path}")
        _apply_texture_settings(texture, clamp=bool(spec.clamp), point_filter=bool(spec.point_filter))
        textures[texture_id] = texture

    widths_data = entries.get("load/smallFnt.dat")
    if widths_data is None:
        raise FileNotFoundError("Missing runtime font widths: load/smallFnt.dat")

    resources = RuntimeResources(
        assets_dir=Path(assets_dir),
        textures=textures,
        logos=_build_logo_assets(textures),
        small_font_widths=list(widths_data),
    )
    register_runtime_resources(resources)
    return resources


def unload_runtime_resources(resources: RuntimeResources | None) -> None:
    if resources is None:
        return
    unregister_runtime_resources(resources.assets_dir)
    resources.unload()
