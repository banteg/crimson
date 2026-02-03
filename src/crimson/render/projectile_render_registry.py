from __future__ import annotations

from dataclasses import dataclass

from ..projectiles import ProjectileTypeId


@dataclass(frozen=True, slots=True)
class PlasmaProjectileRenderConfig:
    rgb: tuple[float, float, float]
    spacing: float
    seg_limit: int
    tail_size: float
    head_size: float
    head_alpha_mul: float
    aura_rgb: tuple[float, float, float]
    aura_size: float
    aura_alpha_mul: float


_DEFAULT_PLASMA_RENDER_CONFIG = PlasmaProjectileRenderConfig(
    rgb=(1.0, 1.0, 1.0),
    spacing=2.1,
    seg_limit=3,
    tail_size=12.0,
    head_size=16.0,
    head_alpha_mul=0.45,
    aura_rgb=(1.0, 1.0, 1.0),
    aura_size=120.0,
    aura_alpha_mul=0.15,
)


PLASMA_PROJECTILE_RENDER_CONFIG_BY_TYPE_ID: dict[int, PlasmaProjectileRenderConfig] = {
    int(ProjectileTypeId.PLASMA_RIFLE): PlasmaProjectileRenderConfig(
        rgb=(1.0, 1.0, 1.0),
        spacing=2.5,
        seg_limit=8,
        tail_size=22.0,
        head_size=56.0,
        head_alpha_mul=0.45,
        aura_rgb=(1.0, 1.0, 1.0),
        aura_size=256.0,
        aura_alpha_mul=0.3,
    ),
    int(ProjectileTypeId.PLASMA_MINIGUN): _DEFAULT_PLASMA_RENDER_CONFIG,
    int(ProjectileTypeId.PLASMA_CANNON): PlasmaProjectileRenderConfig(
        rgb=(1.0, 1.0, 1.0),
        spacing=2.6,
        seg_limit=18,
        tail_size=44.0,
        head_size=84.0,
        head_alpha_mul=0.45,
        aura_rgb=(1.0, 1.0, 1.0),
        aura_size=256.0,
        aura_alpha_mul=0.4,
    ),
    int(ProjectileTypeId.SPIDER_PLASMA): PlasmaProjectileRenderConfig(
        rgb=(0.3, 1.0, 0.3),
        spacing=_DEFAULT_PLASMA_RENDER_CONFIG.spacing,
        seg_limit=_DEFAULT_PLASMA_RENDER_CONFIG.seg_limit,
        tail_size=_DEFAULT_PLASMA_RENDER_CONFIG.tail_size,
        head_size=_DEFAULT_PLASMA_RENDER_CONFIG.head_size,
        head_alpha_mul=_DEFAULT_PLASMA_RENDER_CONFIG.head_alpha_mul,
        aura_rgb=(0.3, 1.0, 0.3),
        aura_size=_DEFAULT_PLASMA_RENDER_CONFIG.aura_size,
        aura_alpha_mul=_DEFAULT_PLASMA_RENDER_CONFIG.aura_alpha_mul,
    ),
    int(ProjectileTypeId.SHRINKIFIER): PlasmaProjectileRenderConfig(
        rgb=(0.3, 0.3, 1.0),
        spacing=_DEFAULT_PLASMA_RENDER_CONFIG.spacing,
        seg_limit=_DEFAULT_PLASMA_RENDER_CONFIG.seg_limit,
        tail_size=_DEFAULT_PLASMA_RENDER_CONFIG.tail_size,
        head_size=_DEFAULT_PLASMA_RENDER_CONFIG.head_size,
        head_alpha_mul=_DEFAULT_PLASMA_RENDER_CONFIG.head_alpha_mul,
        aura_rgb=(0.3, 0.3, 1.0),
        aura_size=_DEFAULT_PLASMA_RENDER_CONFIG.aura_size,
        aura_alpha_mul=_DEFAULT_PLASMA_RENDER_CONFIG.aura_alpha_mul,
    ),
}


def plasma_projectile_render_config(type_id: int) -> PlasmaProjectileRenderConfig:
    return PLASMA_PROJECTILE_RENDER_CONFIG_BY_TYPE_ID.get(int(type_id), _DEFAULT_PLASMA_RENDER_CONFIG)


BEAM_EFFECT_SCALE_BY_TYPE_ID: dict[int, float] = {
    int(ProjectileTypeId.ION_MINIGUN): 1.05,
    int(ProjectileTypeId.ION_RIFLE): 2.2,
    int(ProjectileTypeId.ION_CANNON): 3.5,
}


def beam_effect_scale(type_id: int) -> float:
    return float(BEAM_EFFECT_SCALE_BY_TYPE_ID.get(int(type_id), 0.8))


KNOWN_PROJ_RGB_BY_TYPE_ID: dict[int, tuple[int, int, int]] = {
    int(ProjectileTypeId.ION_RIFLE): (120, 200, 255),
    int(ProjectileTypeId.ION_MINIGUN): (120, 200, 255),
    int(ProjectileTypeId.ION_CANNON): (120, 200, 255),
    int(ProjectileTypeId.FIRE_BULLETS): (255, 170, 90),
    int(ProjectileTypeId.SHRINKIFIER): (160, 255, 170),
    int(ProjectileTypeId.BLADE_GUN): (240, 120, 255),
}


def known_proj_rgb(type_id: int) -> tuple[int, int, int]:
    return KNOWN_PROJ_RGB_BY_TYPE_ID.get(int(type_id), (240, 220, 160))

