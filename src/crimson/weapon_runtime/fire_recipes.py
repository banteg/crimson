from __future__ import annotations

import msgspec

from ..effects import ParticleStyleId
from ..projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from ..weapons import WeaponId, projectile_type_id_for_weapon_id


class NoJitter(msgspec.Struct, frozen=True, tag=True):
    pass


class ModuloCenteredJitter(msgspec.Struct, frozen=True, tag=True):
    modulo: int
    center: int
    step: float


class MaskCenteredJitter(msgspec.Struct, frozen=True, tag=True):
    mask: int
    center: int
    step: float


type PelletJitterRule = NoJitter | ModuloCenteredJitter | MaskCenteredJitter


class NoSpeedScale(msgspec.Struct, frozen=True, tag=True):
    pass


class ModuloSpeedScale(msgspec.Struct, frozen=True, tag=True):
    base: float
    modulo: int
    step: float


type SpeedScaleRule = NoSpeedScale | ModuloSpeedScale


class NoTargetHint(msgspec.Struct, frozen=True, tag=True):
    pass


class UseAimTargetHint(msgspec.Struct, frozen=True, tag=True):
    pass


type SecondaryTargetingPolicy = NoTargetHint | UseAimTargetHint


class PrimaryPelletsMode(msgspec.Struct, frozen=True, tag=True):
    type_id: ProjectileTemplateId | None = None
    count: int | None = None
    jitter: PelletJitterRule = msgspec.field(default_factory=NoJitter)
    speed_scale: SpeedScaleRule = msgspec.field(default_factory=NoSpeedScale)


class SecondaryShotMode(msgspec.Struct, frozen=True, tag=True):
    type_id: SecondaryProjectileTypeId
    targeting: SecondaryTargetingPolicy = msgspec.field(default_factory=NoTargetHint)


class ParticleStreamMode(msgspec.Struct, frozen=True, tag=True):
    style: ParticleStyleId | None = None
    slow: bool = False


class MultiPlasmaFanMode(msgspec.Struct, frozen=True, tag=True):
    pass


class SwarmerDumpMode(msgspec.Struct, frozen=True, tag=True):
    pass


type FireMode = PrimaryPelletsMode | SecondaryShotMode | ParticleStreamMode | MultiPlasmaFanMode | SwarmerDumpMode


class FireRecipe(msgspec.Struct, frozen=True):
    mode: FireMode
    ammo_cost: float = 1.0


def pellet_jitter_step_for_weapon(weapon_id: WeaponId) -> float:
    weapon_id = WeaponId(weapon_id)
    if weapon_id == WeaponId.SHOTGUN:
        return 0.0013
    if weapon_id == WeaponId.SAWED_OFF_SHOTGUN:
        return 0.004
    if weapon_id == WeaponId.JACKHAMMER:
        return 0.0013
    return 0.0015


_SHOTGUN_SPEED_RANDOMIZE_WEAPONS: frozenset[WeaponId] = frozenset(
    {
        WeaponId.SHOTGUN,
        WeaponId.SAWED_OFF_SHOTGUN,
        WeaponId.JACKHAMMER,
    },
)


_DEFAULT_SPREAD_JITTER = ModuloCenteredJitter(modulo=200, center=100, step=0.0015)
_DEFAULT_SPEED_SCALE = ModuloSpeedScale(base=1.0, modulo=100, step=0.01)
_GAUSS_ION_SPEED_SCALE = ModuloSpeedScale(base=1.4, modulo=0x50, step=0.01)


FIRE_RECIPE_BY_WEAPON: dict[WeaponId, FireRecipe] = {
    WeaponId.ROCKET_LAUNCHER: FireRecipe(mode=SecondaryShotMode(type_id=SecondaryProjectileTypeId.ROCKET)),
    WeaponId.SEEKER_ROCKETS: FireRecipe(
        mode=SecondaryShotMode(
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
            targeting=UseAimTargetHint(),
        ),
    ),
    WeaponId.ROCKET_MINIGUN: FireRecipe(mode=SecondaryShotMode(type_id=SecondaryProjectileTypeId.ROCKET_MINIGUN)),
    WeaponId.FLAMETHROWER: FireRecipe(
        mode=ParticleStreamMode(style=None, slow=False),
        ammo_cost=0.1,
    ),
    WeaponId.BLOW_TORCH: FireRecipe(
        mode=ParticleStreamMode(style=ParticleStyleId.BLOW_TORCH, slow=False),
        ammo_cost=0.05,
    ),
    WeaponId.HR_FLAMER: FireRecipe(
        mode=ParticleStreamMode(style=ParticleStyleId.HR_FLAMER, slow=False),
        ammo_cost=0.1,
    ),
    WeaponId.BUBBLEGUN: FireRecipe(
        mode=ParticleStreamMode(style=None, slow=True),
        ammo_cost=0.15,
    ),
    WeaponId.MULTI_PLASMA: FireRecipe(mode=MultiPlasmaFanMode()),
    WeaponId.MINI_ROCKET_SWARMERS: FireRecipe(mode=SwarmerDumpMode()),
    WeaponId.PLASMA_SHOTGUN: FireRecipe(
        mode=PrimaryPelletsMode(
            type_id=ProjectileTemplateId.PLASMA_MINIGUN,
            count=14,
            jitter=MaskCenteredJitter(mask=0xFF, center=0x80, step=0.002),
            speed_scale=_DEFAULT_SPEED_SCALE,
        ),
    ),
    WeaponId.GAUSS_SHOTGUN: FireRecipe(
        mode=PrimaryPelletsMode(
            type_id=ProjectileTemplateId.GAUSS_GUN,
            count=6,
            jitter=ModuloCenteredJitter(modulo=200, center=100, step=0.002),
            speed_scale=_GAUSS_ION_SPEED_SCALE,
        ),
    ),
    WeaponId.ION_SHOTGUN: FireRecipe(
        mode=PrimaryPelletsMode(
            type_id=ProjectileTemplateId.ION_MINIGUN,
            count=8,
            jitter=ModuloCenteredJitter(modulo=200, center=100, step=0.0026),
            speed_scale=_GAUSS_ION_SPEED_SCALE,
        ),
    ),
}


def resolve_fire_recipe(
    weapon_id: WeaponId,
    *,
    pellet_count: int,
    fire_bullets_active: bool,
) -> FireRecipe:
    if fire_bullets_active:
        return FireRecipe(
            mode=PrimaryPelletsMode(
                type_id=ProjectileTemplateId.FIRE_BULLETS,
                count=max(0, int(pellet_count)),
                jitter=_DEFAULT_SPREAD_JITTER,
                speed_scale=NoSpeedScale(),
            ),
        )

    recipe = FIRE_RECIPE_BY_WEAPON.get(WeaponId(weapon_id))
    if recipe is not None:
        return recipe

    pellets = max(1, int(pellet_count))
    jitter: PelletJitterRule = NoJitter()
    if pellets > 1:
        jitter = ModuloCenteredJitter(
            modulo=200,
            center=100,
            step=pellet_jitter_step_for_weapon(weapon_id),
        )

    speed_scale: SpeedScaleRule = NoSpeedScale()
    if pellets > 1 and WeaponId(weapon_id) in _SHOTGUN_SPEED_RANDOMIZE_WEAPONS:
        speed_scale = _DEFAULT_SPEED_SCALE

    return FireRecipe(
        mode=PrimaryPelletsMode(
            type_id=projectile_type_id_for_weapon_id(WeaponId(weapon_id)),
            count=pellets,
            jitter=jitter,
            speed_scale=speed_scale,
        ),
    )


__all__ = [
    "FIRE_RECIPE_BY_WEAPON",
    "FireMode",
    "FireRecipe",
    "MaskCenteredJitter",
    "ModuloCenteredJitter",
    "ModuloSpeedScale",
    "MultiPlasmaFanMode",
    "NoJitter",
    "NoSpeedScale",
    "NoTargetHint",
    "ParticleStreamMode",
    "PelletJitterRule",
    "PrimaryPelletsMode",
    "SecondaryShotMode",
    "SecondaryTargetingPolicy",
    "SpeedScaleRule",
    "SwarmerDumpMode",
    "UseAimTargetHint",
    "pellet_jitter_step_for_weapon",
    "resolve_fire_recipe",
]
