from __future__ import annotations

from crimson.projectiles.types import ProjectileTemplateId
from crimson.render.projectile_draw.primary_plasma import plasma_trail_segment_count, plasma_uses_bullet_core
from crimson.render.projectile_render_registry import (
    beam_effect_scale,
    known_proj_rgb,
    plasma_projectile_render_config,
)


def test_plasma_projectile_render_config_plasma_rifle() -> None:
    cfg = plasma_projectile_render_config(int(ProjectileTemplateId.PLASMA_RIFLE))
    assert cfg.spacing == 2.5
    assert cfg.seg_limit == 8
    assert cfg.tail_size == 22.0
    assert cfg.head_size == 56.0
    assert cfg.aura_size == 256.0
    assert cfg.aura_alpha_mul == 0.3


def test_plasma_projectile_render_config_spider_plasma_is_green() -> None:
    cfg = plasma_projectile_render_config(int(ProjectileTemplateId.SPIDER_PLASMA))
    assert cfg.rgb == (0.3, 1.0, 0.3)
    assert cfg.aura_rgb == (0.3, 1.0, 0.3)


def test_plasma_trail_segment_count_uses_distance_and_integer_divisor() -> None:
    assert (
        plasma_trail_segment_count(
            distance=20.9,
            speed_scale=1.0,
            spacing=2.5,
            limit=8,
        )
        == 8
    )
    assert (
        plasma_trail_segment_count(
            distance=11.9,
            speed_scale=1.55,
            spacing=2.5,
            limit=8,
        )
        == 3
    )


def test_plasma_trail_segment_count_clamps_and_rejects_zero_divisor() -> None:
    assert (
        plasma_trail_segment_count(
            distance=100.0,
            speed_scale=1.0,
            spacing=2.1,
            limit=3,
        )
        == 3
    )
    assert (
        plasma_trail_segment_count(
            distance=100.0,
            speed_scale=0.0,
            spacing=2.1,
            limit=3,
        )
        == 0
    )


def test_plasma_bullet_core_matches_native_late_pass_types() -> None:
    assert plasma_uses_bullet_core(ProjectileTemplateId.SHRINKIFIER)
    assert plasma_uses_bullet_core(ProjectileTemplateId.SPIDER_PLASMA)
    assert plasma_uses_bullet_core(ProjectileTemplateId.PLASMA_CANNON)
    assert not plasma_uses_bullet_core(ProjectileTemplateId.PLASMA_RIFLE)
    assert not plasma_uses_bullet_core(ProjectileTemplateId.PLASMA_MINIGUN)


def test_beam_effect_scale_ion_types() -> None:
    assert beam_effect_scale(int(ProjectileTemplateId.ION_MINIGUN)) == 1.05
    assert beam_effect_scale(int(ProjectileTemplateId.ION_RIFLE)) == 2.2
    assert beam_effect_scale(int(ProjectileTemplateId.ION_CANNON)) == 3.5


def test_beam_effect_scale_defaults_to_fire_bullets() -> None:
    assert beam_effect_scale(int(ProjectileTemplateId.FIRE_BULLETS)) == 0.8


def test_known_proj_rgb_defaults() -> None:
    assert known_proj_rgb(int(ProjectileTemplateId.BLADE_GUN)) == (240, 120, 255)
    assert known_proj_rgb(0xDEADBEEF) == (240, 220, 160)
