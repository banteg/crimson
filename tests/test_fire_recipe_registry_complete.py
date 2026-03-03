from __future__ import annotations

from crimson.projectiles.types import ProjectileTemplateId
from crimson.weapon_runtime.fire_recipes import (
    FIRE_RECIPE_BY_WEAPON,
    MultiPlasmaFanMode,
    ParticleStreamMode,
    PrimaryPelletsMode,
    SecondaryShotMode,
    SwarmerDumpMode,
    resolve_fire_recipe,
)
from crimson.weapons import WeaponId


def test_fire_recipe_registry_declares_expected_special_modes() -> None:
    assert isinstance(FIRE_RECIPE_BY_WEAPON[WeaponId.MULTI_PLASMA].mode, MultiPlasmaFanMode)
    assert isinstance(FIRE_RECIPE_BY_WEAPON[WeaponId.MINI_ROCKET_SWARMERS].mode, SwarmerDumpMode)

    for weapon_id in (
        WeaponId.FLAMETHROWER,
        WeaponId.BLOW_TORCH,
        WeaponId.HR_FLAMER,
        WeaponId.BUBBLEGUN,
    ):
        assert isinstance(FIRE_RECIPE_BY_WEAPON[weapon_id].mode, ParticleStreamMode)

    for weapon_id in (
        WeaponId.ROCKET_LAUNCHER,
        WeaponId.SEEKER_ROCKETS,
        WeaponId.ROCKET_MINIGUN,
    ):
        assert isinstance(FIRE_RECIPE_BY_WEAPON[weapon_id].mode, SecondaryShotMode)


def test_fire_recipe_resolver_returns_default_primary_mode_for_non_special_weapons() -> None:
    recipe = resolve_fire_recipe(
        WeaponId.PISTOL,
        pellet_count=1,
        fire_bullets_active=False,
    )
    assert isinstance(recipe.mode, PrimaryPelletsMode)
    assert recipe.mode.type_id == ProjectileTemplateId.PISTOL


def test_fire_recipe_resolver_applies_fire_bullets_override_mode() -> None:
    recipe = resolve_fire_recipe(
        WeaponId.SHOTGUN,
        pellet_count=12,
        fire_bullets_active=True,
    )
    assert isinstance(recipe.mode, PrimaryPelletsMode)
    assert recipe.mode.type_id == ProjectileTemplateId.FIRE_BULLETS
    assert recipe.mode.count == 12
