from __future__ import annotations

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


class LingerDefault(msgspec.Struct, frozen=True, tag=True):
    pass


class LingerGauss(msgspec.Struct, frozen=True, tag=True):
    pass


class LingerIonRifle(msgspec.Struct, frozen=True, tag=True):
    pass


class LingerIonMinigun(msgspec.Struct, frozen=True, tag=True):
    pass


class LingerIonCannon(msgspec.Struct, frozen=True, tag=True):
    pass


type LingerRule = LingerDefault | LingerGauss | LingerIonRifle | LingerIonMinigun | LingerIonCannon


class PreHitNone(msgspec.Struct, frozen=True, tag=True):
    pass


class PreHitSplitter(msgspec.Struct, frozen=True, tag=True):
    pass


type PreHitRule = PreHitNone | PreHitSplitter


class PostHitNone(msgspec.Struct, frozen=True, tag=True):
    pass


class PostHitIonCommon(msgspec.Struct, frozen=True, tag=True):
    pass


class PostHitIonRifle(msgspec.Struct, frozen=True, tag=True):
    pass


class PostHitPlasmaCannon(msgspec.Struct, frozen=True, tag=True):
    pass


class PostHitShrinkifier(msgspec.Struct, frozen=True, tag=True):
    pass


class PostHitPulsePush(msgspec.Struct, frozen=True, tag=True):
    pass


class PostHitPlagueInfect(msgspec.Struct, frozen=True, tag=True):
    pass


type PostHitRule = (
    PostHitNone
    | PostHitIonCommon
    | PostHitIonRifle
    | PostHitPlasmaCannon
    | PostHitShrinkifier
    | PostHitPulsePush
    | PostHitPlagueInfect
)


class PrimaryProjectileRule(msgspec.Struct, frozen=True):
    linger: LingerRule
    pre_hit: PreHitRule = msgspec.field(default_factory=PreHitNone)
    post_hit: PostHitRule = msgspec.field(default_factory=PostHitNone)
    stop_on_hit: bool = True
    emit_freeze_shard: bool = True
    reset_shock_chain_on_linger: bool = False


_DEFAULT_RULE = PrimaryProjectileRule(linger=LingerDefault())


PRIMARY_PROJECTILE_RULE_BY_TYPE_ID: dict[ProjectileTemplateId, PrimaryProjectileRule] = {
    ProjectileTemplateId.GAUSS_GUN: PrimaryProjectileRule(
        linger=LingerGauss(),
        stop_on_hit=False,
        emit_freeze_shard=False,
    ),
    ProjectileTemplateId.FIRE_BULLETS: PrimaryProjectileRule(
        linger=LingerDefault(),
        stop_on_hit=False,
        emit_freeze_shard=False,
    ),
    ProjectileTemplateId.BLADE_GUN: PrimaryProjectileRule(
        linger=LingerDefault(),
        stop_on_hit=False,
    ),
    ProjectileTemplateId.PULSE_GUN: PrimaryProjectileRule(
        linger=LingerDefault(),
        post_hit=PostHitPulsePush(),
    ),
    ProjectileTemplateId.ION_RIFLE: PrimaryProjectileRule(
        linger=LingerIonRifle(),
        post_hit=PostHitIonRifle(),
        reset_shock_chain_on_linger=True,
    ),
    ProjectileTemplateId.ION_MINIGUN: PrimaryProjectileRule(
        linger=LingerIonMinigun(),
        post_hit=PostHitIonCommon(),
        reset_shock_chain_on_linger=True,
    ),
    ProjectileTemplateId.ION_CANNON: PrimaryProjectileRule(
        linger=LingerIonCannon(),
        post_hit=PostHitIonCommon(),
    ),
    ProjectileTemplateId.SHRINKIFIER: PrimaryProjectileRule(
        linger=LingerDefault(),
        post_hit=PostHitShrinkifier(),
    ),
    ProjectileTemplateId.PLASMA_CANNON: PrimaryProjectileRule(
        linger=LingerDefault(),
        post_hit=PostHitPlasmaCannon(),
    ),
    ProjectileTemplateId.SPLITTER_GUN: PrimaryProjectileRule(
        linger=LingerDefault(),
        pre_hit=PreHitSplitter(),
    ),
    ProjectileTemplateId.PLAGUE_SPREADER: PrimaryProjectileRule(
        linger=LingerDefault(),
        post_hit=PostHitPlagueInfect(),
    ),
}


def primary_rule_for_type_id(type_id: ProjectileTemplateId) -> PrimaryProjectileRule:
    return PRIMARY_PROJECTILE_RULE_BY_TYPE_ID.get(type_id, _DEFAULT_RULE)


def apply_linger(rule: LingerRule, ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    match rule:
        case LingerDefault():
            _linger_default(ctx, proj)
        case LingerGauss():
            _linger_gauss_gun(ctx, proj)
        case LingerIonRifle():
            _linger_ion_rifle(ctx, proj)
        case LingerIonMinigun():
            _linger_ion_minigun(ctx, proj)
        case LingerIonCannon():
            _linger_ion_cannon(ctx, proj)


def apply_pre_hit(rule: PreHitRule, ctx: _ProjectileUpdateCtx, proj: Projectile, hit_idx: int) -> None:
    match rule:
        case PreHitNone():
            return
        case PreHitSplitter():
            _pre_hit_splitter(ctx, proj, hit_idx)


def apply_post_hit(rule: PostHitRule, ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    match rule:
        case PostHitNone():
            return
        case PostHitIonCommon():
            _post_hit_ion_common(ctx, hit)
        case PostHitIonRifle():
            _post_hit_ion_rifle(ctx, hit)
        case PostHitPlasmaCannon():
            _post_hit_plasma_cannon(ctx, hit)
        case PostHitShrinkifier():
            _post_hit_shrinkifier(ctx, hit)
        case PostHitPulsePush():
            _post_hit_pulse_gun(ctx, hit)
        case PostHitPlagueInfect():
            _post_hit_plague_spreader(ctx, hit)


__all__ = [
    "PRIMARY_PROJECTILE_RULE_BY_TYPE_ID",
    "PrimaryProjectileRule",
    "apply_linger",
    "apply_post_hit",
    "apply_pre_hit",
    "primary_rule_for_type_id",
]
