from __future__ import annotations

from crimson.projectiles.runtime import SECONDARY_RULE_BY_TYPE_ID, secondary_rule_for_type_id
from crimson.projectiles.runtime.secondary_rules import DetonationRule, HomingRocketRule, RocketMinigunRule, RocketRule
from crimson.projectiles.types import SecondaryProjectileTypeId


def test_secondary_rule_lookup_covers_known_secondary_types() -> None:
    for type_id in SecondaryProjectileTypeId:
        if type_id == SecondaryProjectileTypeId.NONE:
            continue
        rule = secondary_rule_for_type_id(type_id)
        assert rule is not None


def test_secondary_rule_variants_match_expected_types() -> None:
    assert isinstance(SECONDARY_RULE_BY_TYPE_ID[SecondaryProjectileTypeId.DETONATION], DetonationRule)
    assert isinstance(SECONDARY_RULE_BY_TYPE_ID[SecondaryProjectileTypeId.ROCKET], RocketRule)
    assert isinstance(SECONDARY_RULE_BY_TYPE_ID[SecondaryProjectileTypeId.HOMING_ROCKET], HomingRocketRule)
    assert isinstance(SECONDARY_RULE_BY_TYPE_ID[SecondaryProjectileTypeId.ROCKET_MINIGUN], RocketMinigunRule)
