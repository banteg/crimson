from __future__ import annotations

from crimson.projectiles.runtime import PROJECTILE_BEHAVIOR_BY_TYPE_ID
from crimson.projectiles.types import ProjectileTemplateId


def test_projectile_behavior_registry_covers_projectile_type_enum() -> None:
    for type_id in ProjectileTemplateId:
        assert int(type_id) in PROJECTILE_BEHAVIOR_BY_TYPE_ID

