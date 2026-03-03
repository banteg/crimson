from __future__ import annotations

from .weapons import WEAPON_BY_ID

WEAPON_TABLE_BASE_ADDR = 0x4D7A2C
WEAPON_TABLE_STRIDE_BYTES = 0x7C
WEAPON_TABLE_FIRE_SFX_OFFSET = 0x58
WEAPON_TABLE_RELOAD_SFX_OFFSET = 0x60


def _parse_dat_ref(value: str) -> int | None:
    raw = value.strip()
    if raw.startswith("&"):
        raw = raw[1:]
    raw = raw.lstrip("_")
    if not raw.startswith("DAT_"):
        return None
    try:
        return int(raw.removeprefix("DAT_"), 16)
    except ValueError:
        return None


def _resolve_table_sfx_ref(addr: int) -> str:
    offset = addr - WEAPON_TABLE_BASE_ADDR
    if offset < 0:
        raise ValueError(f"weapon sfx DAT ref below weapon table base: 0x{addr:08x}")

    weapon_id, field_offset = divmod(offset, WEAPON_TABLE_STRIDE_BYTES)
    weapon = WEAPON_BY_ID[weapon_id]
    if field_offset == WEAPON_TABLE_FIRE_SFX_OFFSET:
        return weapon.fire_sound
    if field_offset == WEAPON_TABLE_RELOAD_SFX_OFFSET:
        return weapon.reload_sound
    raise ValueError(
        f"weapon sfx DAT ref points to unsupported field offset 0x{field_offset:02x} (addr=0x{addr:08x})",
    )


def resolve_weapon_sfx_ref(value: str) -> str:
    """
    Resolve weapon-table references like `_DAT_004d93bc` into a concrete sfx key (e.g. `sfx_shotgun_reload`).
    """

    if value.startswith("sfx_"):
        return value

    addr = _parse_dat_ref(value)
    if addr is None:
        raise ValueError(f"unsupported weapon sfx ref format: {value!r}")

    resolved = _resolve_table_sfx_ref(addr)
    if not resolved.startswith("sfx_"):
        raise ValueError(f"weapon sfx ref did not resolve to sfx key: {value!r} -> {resolved!r}")
    return resolved
