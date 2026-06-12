from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import msgspec

from ..types import Projectile, ProjectileTemplateId
from .behaviors import (
    _linger_default,
    _linger_gauss_gun,
    _linger_ion_cannon,
    _linger_ion_minigun,
    _linger_ion_rifle,
    _post_hit_ion_common,
    _post_hit_ion_rifle,
    _post_hit_plague_spreader,
    _post_hit_plasma_cannon,
    _post_hit_pulse_gun,
    _post_hit_shrinkifier,
    _pre_hit_splitter,
)

if TYPE_CHECKING:
    from .behaviors import _ProjectileHitInfo, _ProjectileUpdateCtx


LingerHandler = Callable[["_ProjectileUpdateCtx", Projectile], None]
PreHitHandler = Callable[["_ProjectileUpdateCtx", Projectile, int], None]
PostHitHandler = Callable[["_ProjectileUpdateCtx", "_ProjectileHitInfo"], None]


def _pre_hit_none(_ctx: _ProjectileUpdateCtx, _proj: Projectile, _hit_idx: int) -> None:
    return


def _post_hit_none(_ctx: _ProjectileUpdateCtx, _hit: _ProjectileHitInfo) -> None:
    return


class PrimaryProjectileRule(msgspec.Struct, frozen=True):
    linger: LingerHandler
    pre_hit: PreHitHandler = _pre_hit_none
    post_hit: PostHitHandler = _post_hit_none
    stop_on_hit: bool = True
    reset_shock_chain_on_linger: bool = False


_DEFAULT_RULE = PrimaryProjectileRule(linger=_linger_default)


PRIMARY_PROJECTILE_RULE_BY_TYPE_ID: dict[ProjectileTemplateId, PrimaryProjectileRule] = {
    ProjectileTemplateId.GAUSS_GUN: PrimaryProjectileRule(
        linger=_linger_gauss_gun,
        stop_on_hit=False,
    ),
    ProjectileTemplateId.FIRE_BULLETS: PrimaryProjectileRule(
        linger=_linger_default,
        stop_on_hit=False,
    ),
    ProjectileTemplateId.BLADE_GUN: PrimaryProjectileRule(
        linger=_linger_default,
        stop_on_hit=False,
    ),
    ProjectileTemplateId.PULSE_GUN: PrimaryProjectileRule(
        linger=_linger_default,
        post_hit=_post_hit_pulse_gun,
    ),
    ProjectileTemplateId.ION_RIFLE: PrimaryProjectileRule(
        linger=_linger_ion_rifle,
        post_hit=_post_hit_ion_rifle,
        reset_shock_chain_on_linger=True,
    ),
    ProjectileTemplateId.ION_MINIGUN: PrimaryProjectileRule(
        linger=_linger_ion_minigun,
        post_hit=_post_hit_ion_common,
        reset_shock_chain_on_linger=True,
    ),
    ProjectileTemplateId.ION_CANNON: PrimaryProjectileRule(
        linger=_linger_ion_cannon,
        post_hit=_post_hit_ion_common,
    ),
    ProjectileTemplateId.SHRINKIFIER: PrimaryProjectileRule(
        linger=_linger_default,
        post_hit=_post_hit_shrinkifier,
    ),
    ProjectileTemplateId.PLASMA_CANNON: PrimaryProjectileRule(
        linger=_linger_default,
        post_hit=_post_hit_plasma_cannon,
    ),
    ProjectileTemplateId.SPLITTER_GUN: PrimaryProjectileRule(
        linger=_linger_default,
        pre_hit=_pre_hit_splitter,
    ),
    ProjectileTemplateId.PLAGUE_SPREADER: PrimaryProjectileRule(
        linger=_linger_default,
        post_hit=_post_hit_plague_spreader,
    ),
}


def primary_rule_for_type_id(type_id: ProjectileTemplateId) -> PrimaryProjectileRule:
    return PRIMARY_PROJECTILE_RULE_BY_TYPE_ID.get(type_id, _DEFAULT_RULE)


__all__ = [
    "PRIMARY_PROJECTILE_RULE_BY_TYPE_ID",
    "PrimaryProjectileRule",
    "primary_rule_for_type_id",
]
