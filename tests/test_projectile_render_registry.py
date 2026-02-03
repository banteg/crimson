from __future__ import annotations

from crimson.projectiles import ProjectileTypeId
from crimson.render.projectile_render_registry import (
    beam_effect_scale,
    known_proj_rgb,
    plasma_projectile_render_config,
)


def test_plasma_projectile_render_config_plasma_rifle() -> None:
    cfg = plasma_projectile_render_config(int(ProjectileTypeId.PLASMA_RIFLE))
    assert cfg.spacing == 2.5
    assert cfg.seg_limit == 8
    assert cfg.tail_size == 22.0
    assert cfg.head_size == 56.0
    assert cfg.aura_size == 256.0
    assert cfg.aura_alpha_mul == 0.3


def test_plasma_projectile_render_config_spider_plasma_is_green() -> None:
    cfg = plasma_projectile_render_config(int(ProjectileTypeId.SPIDER_PLASMA))
    assert cfg.rgb == (0.3, 1.0, 0.3)
    assert cfg.aura_rgb == (0.3, 1.0, 0.3)


def test_beam_effect_scale_ion_types() -> None:
    assert beam_effect_scale(int(ProjectileTypeId.ION_MINIGUN)) == 1.05
    assert beam_effect_scale(int(ProjectileTypeId.ION_RIFLE)) == 2.2
    assert beam_effect_scale(int(ProjectileTypeId.ION_CANNON)) == 3.5


def test_beam_effect_scale_defaults_to_fire_bullets() -> None:
    assert beam_effect_scale(int(ProjectileTypeId.FIRE_BULLETS)) == 0.8


def test_known_proj_rgb_defaults() -> None:
    assert known_proj_rgb(int(ProjectileTypeId.BLADE_GUN)) == (240, 120, 255)
    assert known_proj_rgb(0xDEADBEEF) == (240, 220, 160)

