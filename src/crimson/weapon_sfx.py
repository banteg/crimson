from __future__ import annotations

_WEAPON_SFX_ALIASES: dict[str, str] = {
    "_DAT_004d7b7c": "sfx_autorifle_fire",
    "_DAT_004d83c0": "sfx_autorifle_reload",
    "_DAT_004d8434": "sfx_shotgun_fire",
    "_DAT_004d86a8": "sfx_shock_reload",
    "_DAT_004d92bc": "sfx_bloodspill_01",
    "_DAT_004d93b4": "sfx_explosion_large",
    "_DAT_004d93bc": "sfx_shotgun_reload",
}


def resolve_weapon_sfx_ref(value: str) -> str:
    """Resolve legacy `_DAT_...` aliases to concrete `sfx_*` keys."""

    if value.startswith("sfx_"):
        return value

    alias = _WEAPON_SFX_ALIASES.get(value)
    if alias is not None:
        return alias

    raise ValueError(f"unsupported weapon sfx ref format: {value!r}")
