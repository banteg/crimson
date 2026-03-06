from __future__ import annotations

from crimson.projectiles.runtime import PRIMARY_PROJECTILE_RULE_BY_TYPE_ID, primary_rule_for_type_id
from crimson.projectiles.types import ProjectileTemplateId


def test_primary_rule_lookup_covers_every_projectile_type() -> None:
    for type_id in ProjectileTemplateId:
        rule = primary_rule_for_type_id(type_id)
        assert rule.linger is not None


def test_primary_rule_overrides_keep_non_default_entries_only() -> None:
    assert ProjectileTemplateId.PISTOL not in PRIMARY_PROJECTILE_RULE_BY_TYPE_ID
    assert ProjectileTemplateId.GAUSS_GUN in PRIMARY_PROJECTILE_RULE_BY_TYPE_ID
    assert ProjectileTemplateId.ION_RIFLE in PRIMARY_PROJECTILE_RULE_BY_TYPE_ID
