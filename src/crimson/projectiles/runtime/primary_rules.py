from __future__ import annotations

from enum import Enum, auto
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


class LingerRule(Enum):
    DEFAULT = auto()
    GAUSS = auto()
    ION_RIFLE = auto()
    ION_MINIGUN = auto()
    ION_CANNON = auto()


class PreHitRule(Enum):
    NONE = auto()
    SPLITTER = auto()


class PostHitRule(Enum):
    NONE = auto()
    ION_COMMON = auto()
    ION_RIFLE = auto()
    PLASMA_CANNON = auto()
    SHRINKIFIER = auto()
    PULSE_PUSH = auto()
    PLAGUE_INFECT = auto()


class PrimaryProjectileRule(msgspec.Struct, frozen=True):
    linger: LingerRule
    pre_hit: PreHitRule = PreHitRule.NONE
    post_hit: PostHitRule = PostHitRule.NONE
    stop_on_hit: bool = True
    emit_freeze_shard: bool = True
    reset_shock_chain_on_linger: bool = False


_DEFAULT_RULE = PrimaryProjectileRule(linger=LingerRule.DEFAULT)


PRIMARY_PROJECTILE_RULE_BY_TYPE_ID: dict[ProjectileTemplateId, PrimaryProjectileRule] = {
    ProjectileTemplateId.GAUSS_GUN: PrimaryProjectileRule(
        linger=LingerRule.GAUSS,
        stop_on_hit=False,
        emit_freeze_shard=False,
    ),
    ProjectileTemplateId.FIRE_BULLETS: PrimaryProjectileRule(
        linger=LingerRule.DEFAULT,
        stop_on_hit=False,
        emit_freeze_shard=False,
    ),
    ProjectileTemplateId.BLADE_GUN: PrimaryProjectileRule(
        linger=LingerRule.DEFAULT,
        stop_on_hit=False,
    ),
    ProjectileTemplateId.PULSE_GUN: PrimaryProjectileRule(
        linger=LingerRule.DEFAULT,
        post_hit=PostHitRule.PULSE_PUSH,
    ),
    ProjectileTemplateId.ION_RIFLE: PrimaryProjectileRule(
        linger=LingerRule.ION_RIFLE,
        post_hit=PostHitRule.ION_RIFLE,
        reset_shock_chain_on_linger=True,
    ),
    ProjectileTemplateId.ION_MINIGUN: PrimaryProjectileRule(
        linger=LingerRule.ION_MINIGUN,
        post_hit=PostHitRule.ION_COMMON,
        reset_shock_chain_on_linger=True,
    ),
    ProjectileTemplateId.ION_CANNON: PrimaryProjectileRule(
        linger=LingerRule.ION_CANNON,
        post_hit=PostHitRule.ION_COMMON,
    ),
    ProjectileTemplateId.SHRINKIFIER: PrimaryProjectileRule(
        linger=LingerRule.DEFAULT,
        post_hit=PostHitRule.SHRINKIFIER,
    ),
    ProjectileTemplateId.PLASMA_CANNON: PrimaryProjectileRule(
        linger=LingerRule.DEFAULT,
        post_hit=PostHitRule.PLASMA_CANNON,
    ),
    ProjectileTemplateId.SPLITTER_GUN: PrimaryProjectileRule(
        linger=LingerRule.DEFAULT,
        pre_hit=PreHitRule.SPLITTER,
    ),
    ProjectileTemplateId.PLAGUE_SPREADER: PrimaryProjectileRule(
        linger=LingerRule.DEFAULT,
        post_hit=PostHitRule.PLAGUE_INFECT,
    ),
}


def primary_rule_for_type_id(type_id: ProjectileTemplateId) -> PrimaryProjectileRule:
    return PRIMARY_PROJECTILE_RULE_BY_TYPE_ID.get(type_id, _DEFAULT_RULE)


def apply_linger(rule: LingerRule, ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    match rule:
        case LingerRule.DEFAULT:
            _linger_default(ctx, proj)
        case LingerRule.GAUSS:
            _linger_gauss_gun(ctx, proj)
        case LingerRule.ION_RIFLE:
            _linger_ion_rifle(ctx, proj)
        case LingerRule.ION_MINIGUN:
            _linger_ion_minigun(ctx, proj)
        case LingerRule.ION_CANNON:
            _linger_ion_cannon(ctx, proj)
        case _:
            raise AssertionError(f"Unsupported linger rule: {rule!r}")


def apply_pre_hit(rule: PreHitRule, ctx: _ProjectileUpdateCtx, proj: Projectile, hit_idx: int) -> None:
    match rule:
        case PreHitRule.NONE:
            return
        case PreHitRule.SPLITTER:
            _pre_hit_splitter(ctx, proj, hit_idx)
        case _:
            raise AssertionError(f"Unsupported pre-hit rule: {rule!r}")


def apply_post_hit(rule: PostHitRule, ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    match rule:
        case PostHitRule.NONE:
            return
        case PostHitRule.ION_COMMON:
            _post_hit_ion_common(ctx, hit)
        case PostHitRule.ION_RIFLE:
            _post_hit_ion_rifle(ctx, hit)
        case PostHitRule.PLASMA_CANNON:
            _post_hit_plasma_cannon(ctx, hit)
        case PostHitRule.SHRINKIFIER:
            _post_hit_shrinkifier(ctx, hit)
        case PostHitRule.PULSE_PUSH:
            _post_hit_pulse_gun(ctx, hit)
        case PostHitRule.PLAGUE_INFECT:
            _post_hit_plague_spreader(ctx, hit)
        case _:
            raise AssertionError(f"Unsupported post-hit rule: {rule!r}")


__all__ = [
    "PRIMARY_PROJECTILE_RULE_BY_TYPE_ID",
    "PrimaryProjectileRule",
    "apply_linger",
    "apply_post_hit",
    "apply_pre_hit",
    "primary_rule_for_type_id",
]
