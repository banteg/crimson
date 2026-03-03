from __future__ import annotations

from crimson.projectiles.runtime import PROJECTILE_BEHAVIOR_BY_TYPE_ID, projectile_behavior_for_type_id
from crimson.projectiles.types import ProjectileTemplateId


def test_projectile_behavior_registry_covers_projectile_type_enum() -> None:
    for type_id in ProjectileTemplateId:
        behavior = projectile_behavior_for_type_id(type_id)
        assert behavior.linger is not None


def test_projectile_behavior_registry_only_keeps_non_default_overrides() -> None:
    assert int(ProjectileTemplateId.PISTOL) not in PROJECTILE_BEHAVIOR_BY_TYPE_ID
    assert int(ProjectileTemplateId.GAUSS_GUN) in PROJECTILE_BEHAVIOR_BY_TYPE_ID
