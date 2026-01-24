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


def resolve_weapon_sfx_ref(value: str | None, *, max_depth: int = 16) -> str | None:
    """
    Resolve weapon-table references like `_DAT_004d93bc` into a concrete sfx key (e.g. `sfx_shotgun_reload`).
    """

    current = value
    seen_addrs: set[int] = set()

    for _ in range(max(1, int(max_depth))):
        if current is None:
            return None
        if current.startswith("sfx_"):
            return current

        addr = _parse_dat_ref(current)
        if addr is None:
            return current
        if addr in seen_addrs:
            return current
        seen_addrs.add(addr)

        offset = addr - WEAPON_TABLE_BASE_ADDR
        if offset < 0:
            return current
        entry_index, field_offset = divmod(offset, WEAPON_TABLE_STRIDE_BYTES)
        weapon_id = entry_index - 1
        weapon = WEAPON_BY_ID.get(weapon_id)
        if weapon is None:
            return current

        if field_offset == WEAPON_TABLE_FIRE_SFX_OFFSET:
            current = weapon.fire_sound
            continue
        if field_offset == WEAPON_TABLE_RELOAD_SFX_OFFSET:
            current = weapon.reload_sound
            continue

        return current

    return current

