from __future__ import annotations

import io
from contextlib import ExitStack
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import msgspec
from PIL import Image

from grim.raylib_api import rl

from . import jaz, paq
from .shaders import AlphaTestShader

if TYPE_CHECKING:
    from grim.fonts.small import SmallFontData

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
    rel_path: str
    clamp: bool = False
    point_filter: bool = False


TEXTURE_SPECS: Final[dict[TextureId, TextureSpec]] = {
    TextureId.BACKPLASMA: TextureSpec("load/backplasma.jaz"),
    TextureId.MOCKUP: TextureSpec("load/mockup.jaz"),
    TextureId.LOGO_ESRB: TextureSpec("load/esrb_mature.jaz"),
    TextureId.LOADING: TextureSpec("load/loading.jaz"),
    TextureId.CL_LOGO: TextureSpec("load/logo_crimsonland.tga"),
    TextureId.SPLASH_10TONS: TextureSpec("load/splash10tons.jaz"),
    TextureId.SPLASH_REFLEXIVE: TextureSpec("load/splashReflexive.jpg"),
    TextureId.DEFAULT_FONT_COURIER: TextureSpec("load/default_font_courier.tga"),
    TextureId.SMALL_WHITE: TextureSpec("load/smallWhite.tga", point_filter=True),
    TextureId.TROOPER: TextureSpec("game/trooper.jaz"),
    TextureId.ZOMBIE: TextureSpec("game/zombie.jaz"),
    TextureId.SPIDER_SP1: TextureSpec("game/spider_sp1.jaz"),
    TextureId.SPIDER_SP2: TextureSpec("game/spider_sp2.jaz"),
    TextureId.ALIEN: TextureSpec("game/alien.jaz"),
    TextureId.LIZARD: TextureSpec("game/lizard.jaz"),
    TextureId.ARROW: TextureSpec("load/arrow.tga"),
    TextureId.BULLET_I: TextureSpec("load/bullet16.tga"),
    TextureId.BULLET_TRAIL: TextureSpec("load/bulletTrail.tga"),
    TextureId.BODYSET: TextureSpec("game/bodyset.jaz"),
    TextureId.PROJS: TextureSpec("game/projs.jaz"),
    TextureId.UI_ICON_AIM: TextureSpec("ui/ui_iconAim.jaz", clamp=True),
    TextureId.UI_BUTTON_SM: TextureSpec("ui/ui_button_64x32.jaz", clamp=True),
    TextureId.UI_BUTTON_MD: TextureSpec("ui/ui_button_128x32.jaz", clamp=True),
    TextureId.UI_CHECK_ON: TextureSpec("ui/ui_checkOn.jaz", clamp=True),
    TextureId.UI_CHECK_OFF: TextureSpec("ui/ui_checkOff.jaz", clamp=True),
    TextureId.UI_RECT_OFF: TextureSpec("ui/ui_rectOff.jaz", clamp=True),
    TextureId.UI_RECT_ON: TextureSpec("ui/ui_rectOn.jaz", clamp=True),
    TextureId.BONUSES: TextureSpec("game/bonuses.jaz"),
    TextureId.UI_IND_BULLET: TextureSpec("ui/ui_indBullet.jaz", clamp=True),
    TextureId.UI_IND_ROCKET: TextureSpec("ui/ui_indRocket.jaz", clamp=True),
    TextureId.UI_IND_ELECTRIC: TextureSpec("ui/ui_indElectric.jaz", clamp=True),
    TextureId.UI_IND_FIRE: TextureSpec("ui/ui_indFire.jaz", clamp=True),
    TextureId.PARTICLES: TextureSpec("game/particles.jaz"),
    TextureId.UI_IND_LIFE: TextureSpec("ui/ui_indLife.jaz", clamp=True),
    TextureId.UI_IND_PANEL: TextureSpec("ui/ui_indPanel.jaz", clamp=True),
    TextureId.UI_ARROW: TextureSpec("ui/ui_arrow.jaz", clamp=True),
    TextureId.UI_CURSOR: TextureSpec("ui/ui_cursor.jaz", clamp=True),
    TextureId.UI_AIM: TextureSpec("ui/ui_aim.jaz", clamp=True),
    TextureId.TER_Q1_BASE: TextureSpec("ter/ter_q1_base.jaz"),
    TextureId.TER_Q1_OVERLAY: TextureSpec("ter/ter_q1_tex1.jaz"),
    TextureId.TER_Q2_BASE: TextureSpec("ter/ter_q2_base.jaz"),
    TextureId.TER_Q2_OVERLAY: TextureSpec("ter/ter_q2_tex1.jaz"),
    TextureId.TER_Q3_BASE: TextureSpec("ter/ter_q3_base.jaz"),
    TextureId.TER_Q3_OVERLAY: TextureSpec("ter/ter_q3_tex1.jaz"),
    TextureId.TER_Q4_BASE: TextureSpec("ter/ter_q4_base.jaz"),
    TextureId.TER_Q4_OVERLAY: TextureSpec("ter/ter_q4_tex1.jaz"),
    TextureId.UI_TEXT_LEVEL_COMPLETE: TextureSpec("ui/ui_textLevComp.jaz", clamp=True),
    TextureId.UI_TEXT_QUEST: TextureSpec("ui/ui_textQuest.jaz", clamp=True),
    TextureId.UI_NUM1: TextureSpec("ui/ui_num1.jaz", clamp=True),
    TextureId.UI_NUM2: TextureSpec("ui/ui_num2.jaz", clamp=True),
    TextureId.UI_NUM3: TextureSpec("ui/ui_num3.jaz", clamp=True),
    TextureId.UI_NUM4: TextureSpec("ui/ui_num4.jaz", clamp=True),
    TextureId.UI_NUM5: TextureSpec("ui/ui_num5.jaz", clamp=True),
    TextureId.UI_WICONS: TextureSpec("ui/ui_wicons.jaz", clamp=True),
    TextureId.UI_GAME_TOP: TextureSpec("ui/ui_gameTop.jaz", clamp=True),
    TextureId.UI_LIFE_HEART: TextureSpec("ui/ui_lifeHeart.jaz", clamp=True),
    TextureId.UI_CLOCK_TABLE: TextureSpec("ui/ui_clockTable.jaz", clamp=True),
    TextureId.UI_CLOCK_POINTER: TextureSpec("ui/ui_clockPointer.jaz", clamp=True),
    TextureId.MUZZLE_FLASH: TextureSpec("game/muzzleFlash.jaz"),
    TextureId.UI_DROP_ON: TextureSpec("ui/ui_dropDownOn.jaz", clamp=True),
    TextureId.UI_DROP_OFF: TextureSpec("ui/ui_dropDownOff.jaz", clamp=True),
    TextureId.UI_SIGN_CRIMSON: TextureSpec("ui/ui_signCrimson.jaz", clamp=True),
    TextureId.UI_MENU_ITEM: TextureSpec("ui/ui_menuItem.jaz", clamp=True),
    TextureId.UI_MENU_PANEL: TextureSpec("ui/ui_menuPanel.jaz", clamp=True),
    TextureId.UI_ITEM_TEXTS: TextureSpec("ui/ui_itemTexts.jaz", clamp=True),
    TextureId.UI_TEXT_REAPER: TextureSpec("ui/ui_textReaper.jaz", clamp=True),
    TextureId.UI_TEXT_WELL_DONE: TextureSpec("ui/ui_textWellDone.jaz", clamp=True),
    TextureId.UI_TEXT_CONTROLS: TextureSpec("ui/ui_textControls.jaz", clamp=True),
    TextureId.UI_TEXT_PICK_A_PERK: TextureSpec("ui/ui_textPickAPerk.jaz", clamp=True),
    TextureId.UI_TEXT_LEVEL_UP: TextureSpec("ui/ui_textLevelUp.jaz", clamp=True),
}

class RuntimeResources(msgspec.Struct):
    assets_dir: Path
    textures: dict[TextureId, rl.Texture]
    small_font: SmallFontData
    alpha_test: AlphaTestShader = msgspec.field(default_factory=AlphaTestShader)

    def texture(self, texture_id: TextureId) -> rl.Texture:
        texture = self.textures.get(texture_id)
        if texture is None:
            rel_path = TEXTURE_SPECS[texture_id].rel_path
            raise RuntimeError(f"runtime texture is not available: {rel_path}")
        return texture

    def unload(self) -> None:
        self.alpha_test.close()
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


def load_paq_entries_from_path(paq_path: Path) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    if not paq_path.exists():
        raise FileNotFoundError(f"Missing PAQ archive: {paq_path}")
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data
    return entries


def load_paq_entries(assets_dir: Path) -> dict[str, bytes]:
    return load_paq_entries_from_path(Path(assets_dir) / PAQ_NAME)


def _same_stem_source_art_paths(rel_path: str) -> tuple[str, ...]:
    if not rel_path.lower().endswith(".jaz"):
        return ()
    stem = rel_path[:-4]
    return (f"{stem}.tga", f"{stem}.jpg")


def _select_texture_asset(entries: dict[str, bytes], rel_path: str) -> tuple[str, bytes | None]:
    for source_art_path in _same_stem_source_art_paths(rel_path):
        payload = entries.get(source_art_path)
        if payload is not None:
            return source_art_path, payload
    return rel_path, entries.get(rel_path)


def _load_texture_from_bytes(data: bytes, fmt: str) -> rl.Texture:
    image = rl.load_image_from_memory(fmt, cast(str, data), len(data))
    try:
        texture = rl.load_texture_from_image(image)
    finally:
        rl.unload_image(image)
    if int(texture.id) <= 0:
        raise RuntimeError("Could not upload runtime texture")
    try:
        rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
    except Exception:
        rl.unload_texture(texture)
        raise
    return texture


def _apply_texture_settings(texture: rl.Texture, *, clamp: bool, point_filter: bool) -> None:
    if clamp:
        rl.set_texture_wrap(texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
    if point_filter:
        rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_POINT)


def _load_texture_asset_from_bytes(rel_path: str, data: bytes | None) -> rl.Texture | None:
    if data is None:
        raise FileNotFoundError(f"Missing asset data: {rel_path}")
    texture: rl.Texture | None
    if rel_path.lower().endswith(".jaz"):
        jaz_image = jaz.decode_jaz_bytes(data)
        buf = io.BytesIO()
        jaz_image.composite_image().save(buf, format="PNG")
        texture = _load_texture_from_bytes(buf.getvalue(), ".png")
    elif rel_path.lower().endswith(".tga") or rel_path.lower().endswith((".jpg", ".jpeg")):
        img = Image.open(io.BytesIO(data))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        texture = _load_texture_from_bytes(buf.getvalue(), ".png")
    else:
        texture = None
    return texture


def _build_small_font(textures: dict[TextureId, rl.Texture], widths_data: bytes) -> SmallFontData:
    from grim.fonts.small import SmallFontData

    return SmallFontData(
        widths=list(widths_data),
        texture=textures[TextureId.SMALL_WHITE],
    )


def load_runtime_resources(assets_dir: Path) -> RuntimeResources:
    entries = load_paq_entries(Path(assets_dir))
    widths_data = entries.get("load/smallFnt.dat")
    if widths_data is None:
        raise FileNotFoundError("Missing runtime font widths: load/smallFnt.dat")
    if len(widths_data) != 256:
        raise ValueError(f"Runtime font widths must contain 256 entries, got {len(widths_data)}")
    with ExitStack() as cleanup:
        textures: dict[TextureId, rl.Texture] = {}
        for texture_id, spec in TEXTURE_SPECS.items():
            asset_path, payload = _select_texture_asset(entries, spec.rel_path)
            texture = _load_texture_asset_from_bytes(asset_path, payload)
            if texture is None:
                raise FileNotFoundError(f"Missing runtime texture: {spec.rel_path}")
            cleanup.callback(rl.unload_texture, texture)
            _apply_texture_settings(texture, clamp=bool(spec.clamp), point_filter=bool(spec.point_filter))
            textures[texture_id] = texture

        resources = RuntimeResources(
            assets_dir=Path(assets_dir),
            textures=textures,
            small_font=_build_small_font(textures, widths_data),
        )
        register_runtime_resources(resources)
        cleanup.pop_all()
    return resources


def unload_runtime_resources(resources: RuntimeResources | None) -> None:
    if resources is None:
        return
    unregister_runtime_resources(resources.assets_dir)
    resources.unload()
