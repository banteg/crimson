from __future__ import annotations

from dataclasses import dataclass, replace
import math
import os
import random
from typing import Any

import pyray as rl

from grim.audio import AudioState, shutdown_audio, update_audio
from grim.console import ConsoleState
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.view import View, ViewContext

from ..creatures.spawn import SpawnId
from ..game_modes import GameMode
from ..game_world import GameWorld
from ..projectiles import ProjectileTypeId, SecondaryProjectileTypeId
from ..sim.input import PlayerInput
from ..ui.cursor import draw_aim_cursor
from ..weapons import WEAPON_BY_ID, WeaponId
from ._ui_helpers import draw_ui_text, ui_line_height
from .audio_bootstrap import init_view_audio
from .registry import register_view

WORLD_SIZE = 1024.0
WORLD_CENTER = Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5)

BG = rl.Color(10, 10, 12, 255)
UI_TEXT = rl.Color(235, 235, 235, 255)
UI_HINT = rl.Color(180, 180, 180, 255)
UI_WARNING = rl.Color(255, 204, 96, 255)
UI_ERROR = rl.Color(240, 80, 80, 255)

OCCLUDER_COLOR = rl.Color(60, 180, 255, 220)
LIGHT_RING_COLOR = rl.Color(255, 180, 80, 190)
LIGHT_CORE_COLOR = rl.Color(255, 235, 160, 240)
SHADOW_PREVIEW_BG = rl.Color(14, 14, 18, 220)
SHADOW_PREVIEW_BORDER = rl.Color(90, 90, 110, 240)
SHADOW_PREVIEW_CANVAS = rl.Color(176, 176, 176, 255)
SHADOW_PREVIEW_TEXT = rl.Color(215, 215, 215, 255)

SHADOW_RT_SCALE = 0.25
MAX_LIGHTS = 6
MAX_OCCLUDERS = 20
MAX_STEPS = 56

DEFAULT_LIGHT_SIZE_W = 0.30
DEFAULT_SHADOW_STRENGTH = 1.02
DEFAULT_MIN_T = 3.0
DEFAULT_SHADOW_RANGE_SCALE = 1.55
DEFAULT_AMBIENT_DARKNESS = 0.78
DEFAULT_DIRECTIONAL_FOCUS = 1.15
DEFAULT_DIRECTIONAL_STRETCH = 1.25
# Keep temporal accumulation off by default; some backends/drivers produce stale
# blends with the secondary sampler path and hide shadows entirely.
DEFAULT_TEMPORAL_RESPONSE = 1.00
DEFAULT_JITTER_AMOUNT = 1.0

RT_SCALE_MIN = 0.15
RT_SCALE_MAX = 0.75

PLAYER_SPEED_MULTIPLIER = 4.0
PLAYER_INVULNERABLE_SHIELD_TIMER = 1e-3
ENEMY_RING_RADIUS = 280.0

AUTODIAG_ENV = "CRIMSON_LIGHTING_DEBUG_AUTODIAG"
AUTODIAG_FRAMES_DEFAULT = 300
AUTODIAG_SEGMENT_FRAMES = 50
AUTODIAG_LOG_INTERVAL = 15
DUMP_ALL_MODES_ENV = "CRIMSON_LIGHTING_DEBUG_DUMP_ALL_MODES"
DUMP_ALL_SETTLE_FRAMES = 12
DUMP_ALL_EMIT_INTERVAL = 6

SHADOW_DEBUG_MODE_NAMES: tuple[str, ...] = (
    "off",
    "solid",
    "light_count",
    "occluder_count",
    "world_gradient",
    "sdf_distance",
    "light0_radius",
    "occluder0_radius",
)
AUTODIAG_DEBUG_MODE_SEQUENCE: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 7, 0)


@dataclass(frozen=True, slots=True)
class CircleOccluder:
    pos: Vec2
    radius: float


@dataclass(frozen=True, slots=True)
class ShadowLight:
    pos: Vec2
    radius: float
    strength: float
    dir_x: float = 0.0
    dir_y: float = 0.0
    focus: float = 0.0
    stretch: float = 1.0


@dataclass(frozen=True, slots=True)
class TransientLight:
    pos: Vec2
    radius: float
    strength: float
    ttl: float
    age: float = 0.0


@dataclass(frozen=True, slots=True)
class EmissiveProfile:
    name: str
    auto_interval: float
    rate_weapon_id: int | None = None
    primary_type_id: int | None = None
    secondary_type_id: int | None = None
    burst_count: int = 1
    spread_rad: float = 0.0
    spawn_distance: float = 28.0
    secondary_ttl: float = 2.0
    flash_radius: float = 120.0
    flash_ttl: float = 0.2
    flash_strength: float = 1.0
    explosion_distance: float = 110.0


@dataclass(frozen=True, slots=True)
class SpawnPreset:
    name: str
    spawn_id: int
    ring_count: int = 10


@dataclass(frozen=True, slots=True)
class _ShadowUniforms:
    resolution: int
    rt_resolution: int
    camera: int
    view_scale: int
    occluder_count: int
    occluders: tuple[int, ...]
    light_count: int
    lights: tuple[int, ...]
    light_dirs: tuple[int, ...]
    light_size_w: int
    shadow_strength: int
    ambient_darkness: int
    min_t: int
    jitter_phase: int
    jitter_amount: int
    debug_mode: int


@dataclass(frozen=True, slots=True)
class _TemporalUniforms:
    current_tex: int
    response: int


@dataclass(frozen=True, slots=True)
class _TuneParam:
    key: str
    label: str
    minimum: float
    maximum: float
    step: float
    coarse_step: float


EMISSIVE_PROFILES: tuple[EmissiveProfile, ...] = (
    EmissiveProfile(
        name="Muzzle",
        auto_interval=0.11,
        rate_weapon_id=int(WeaponId.PISTOL),
        primary_type_id=int(ProjectileTypeId.PISTOL),
        flash_radius=95.0,
        flash_ttl=0.11,
        flash_strength=1.0,
    ),
    EmissiveProfile(
        name="Ion Rifle",
        auto_interval=0.16,
        rate_weapon_id=int(WeaponId.ION_RIFLE),
        primary_type_id=int(ProjectileTypeId.ION_RIFLE),
        flash_radius=140.0,
        flash_ttl=0.17,
        flash_strength=1.0,
    ),
    EmissiveProfile(
        name="Ion Minigun",
        auto_interval=0.06,
        rate_weapon_id=int(WeaponId.ION_MINIGUN),
        primary_type_id=int(ProjectileTypeId.ION_MINIGUN),
        burst_count=2,
        spread_rad=0.03,
        flash_radius=135.0,
        flash_ttl=0.12,
        flash_strength=0.9,
    ),
    EmissiveProfile(
        name="Plasma Rifle",
        auto_interval=0.13,
        rate_weapon_id=int(WeaponId.PLASMA_RIFLE),
        primary_type_id=int(ProjectileTypeId.PLASMA_RIFLE),
        flash_radius=150.0,
        flash_ttl=0.19,
        flash_strength=1.0,
    ),
    EmissiveProfile(
        name="Plasma Cannon",
        auto_interval=0.27,
        rate_weapon_id=int(WeaponId.PLASMA_CANNON),
        primary_type_id=int(ProjectileTypeId.PLASMA_CANNON),
        flash_radius=210.0,
        flash_ttl=0.24,
        flash_strength=1.0,
    ),
    EmissiveProfile(
        name="Fire/Flame",
        auto_interval=0.08,
        rate_weapon_id=int(WeaponId.HR_FLAMER),
        primary_type_id=int(ProjectileTypeId.FIRE_BULLETS),
        burst_count=4,
        spread_rad=0.16,
        flash_radius=125.0,
        flash_ttl=0.16,
        flash_strength=0.9,
    ),
    EmissiveProfile(
        name="Explosion",
        auto_interval=0.45,
        rate_weapon_id=int(WeaponId.ROCKET_LAUNCHER),
        secondary_type_id=int(SecondaryProjectileTypeId.DETONATION),
        secondary_ttl=0.95,
        flash_radius=280.0,
        flash_ttl=0.3,
        flash_strength=1.0,
        spawn_distance=8.0,
        explosion_distance=120.0,
    ),
)


SPAWN_PRESETS: tuple[SpawnPreset, ...] = (
    SpawnPreset(name="Zombie", spawn_id=int(SpawnId.ZOMBIE_CONST_GREY_42), ring_count=12),
    SpawnPreset(name="Zombie Brute", spawn_id=int(SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43), ring_count=10),
    SpawnPreset(name="Lizard", spawn_id=int(SpawnId.LIZARD_CONST_GREY_2F), ring_count=10),
    SpawnPreset(name="Lizard Boss", spawn_id=int(SpawnId.LIZARD_CONST_YELLOW_BOSS_30), ring_count=8),
    SpawnPreset(name="Alien", spawn_id=int(SpawnId.ALIEN_CONST_GREEN_24), ring_count=10),
    SpawnPreset(name="Alien Brute", spawn_id=int(SpawnId.ALIEN_CONST_GREY_BRUTE_29), ring_count=9),
    SpawnPreset(name="Spider SP1", spawn_id=int(SpawnId.SPIDER_SP1_CONST_BLUE_40), ring_count=11),
    SpawnPreset(name="Spider SP2", spawn_id=int(SpawnId.SPIDER_SP2_RANDOM_35), ring_count=11),
)


_PRIMARY_PROJECTILE_LIGHTS: dict[int, tuple[float, float]] = {
    int(ProjectileTypeId.PISTOL): (105.0, 0.75),
    int(ProjectileTypeId.ION_RIFLE): (235.0, 1.0),
    int(ProjectileTypeId.ION_MINIGUN): (190.0, 0.95),
    int(ProjectileTypeId.PLASMA_RIFLE): (220.0, 1.0),
    int(ProjectileTypeId.PLASMA_CANNON): (275.0, 1.0),
    int(ProjectileTypeId.FIRE_BULLETS): (170.0, 0.9),
}

_SECONDARY_PROJECTILE_LIGHTS: dict[int, tuple[float, float]] = {
    int(SecondaryProjectileTypeId.ROCKET): (230.0, 0.95),
    int(SecondaryProjectileTypeId.HOMING_ROCKET): (245.0, 1.0),
    int(SecondaryProjectileTypeId.DETONATION): (280.0, 1.0),
    int(SecondaryProjectileTypeId.ROCKET_MINIGUN): (180.0, 0.85),
}

_PRIMARY_PROJECTILE_DIRECTIONAL: dict[int, tuple[float, float]] = {
    int(ProjectileTypeId.PISTOL): (0.20, 1.15),
    int(ProjectileTypeId.ION_RIFLE): (0.78, 1.85),
    int(ProjectileTypeId.ION_MINIGUN): (0.72, 1.70),
    int(ProjectileTypeId.PLASMA_RIFLE): (0.78, 1.80),
    int(ProjectileTypeId.PLASMA_CANNON): (0.92, 2.10),
    int(ProjectileTypeId.FIRE_BULLETS): (0.55, 1.45),
}

_SECONDARY_PROJECTILE_DIRECTIONAL: dict[int, tuple[float, float]] = {
    int(SecondaryProjectileTypeId.ROCKET): (0.80, 2.00),
    int(SecondaryProjectileTypeId.HOMING_ROCKET): (0.86, 2.20),
    int(SecondaryProjectileTypeId.DETONATION): (0.0, 1.0),
    int(SecondaryProjectileTypeId.ROCKET_MINIGUN): (0.72, 1.80),
}

_TUNE_PARAMS: tuple[_TuneParam, ...] = (
    _TuneParam("ambient_darkness", "ambient darkness", 0.20, 0.95, 0.02, 0.08),
    _TuneParam("shadow_strength", "light reveal", 0.10, 1.40, 0.03, 0.12),
    _TuneParam("light_size_w", "light size (w)", 0.05, 0.80, 0.01, 0.04),
    _TuneParam("min_t", "min t", 0.5, 24.0, 0.5, 2.0),
    _TuneParam("range_scale", "range scale", 0.6, 2.8, 0.05, 0.2),
    _TuneParam("directional_focus", "dir focus", 0.0, 2.0, 0.05, 0.2),
    _TuneParam("directional_stretch", "dir stretch", 0.5, 2.8, 0.05, 0.2),
    _TuneParam("jitter_amount", "jitter", 0.0, 5.0, 0.1, 0.5),
    _TuneParam("temporal_response", "temporal", 0.02, 1.0, 0.02, 0.1),
    _TuneParam("rt_scale", "shadow rt scale", RT_SCALE_MIN, RT_SCALE_MAX, 0.01, 0.05),
)

_TUNE_DEFAULTS: dict[str, float] = {
    "ambient_darkness": DEFAULT_AMBIENT_DARKNESS,
    "shadow_strength": DEFAULT_SHADOW_STRENGTH,
    "light_size_w": DEFAULT_LIGHT_SIZE_W,
    "min_t": DEFAULT_MIN_T,
    "range_scale": DEFAULT_SHADOW_RANGE_SCALE,
    "directional_focus": DEFAULT_DIRECTIONAL_FOCUS,
    "directional_stretch": DEFAULT_DIRECTIONAL_STRETCH,
    "jitter_amount": DEFAULT_JITTER_AMOUNT,
    "temporal_response": DEFAULT_TEMPORAL_RESPONSE,
    "rt_scale": SHADOW_RT_SCALE,
}

_SHADOW_VS_330 = """
#version 330

in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;

out vec2 fragTexCoord;
out vec4 fragColor;

uniform mat4 mvp;

void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

_SHADOW_FS_330 = """
#version 330

#define MAX_OCCLUDERS %d
#define MAX_LIGHTS %d
#define MAX_STEPS %d

in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;

uniform vec2 u_resolution;
uniform vec2 u_rt_resolution;
uniform vec2 u_camera;
uniform vec2 u_view_scale;
uniform int u_occluder_count;
uniform vec4 u_occluders[MAX_OCCLUDERS];
uniform int u_light_count;
uniform vec4 u_lights[MAX_LIGHTS];
uniform vec4 u_light_dirs[MAX_LIGHTS];
uniform float u_light_size_w;
uniform float u_shadow_strength;
uniform float u_ambient_darkness;
uniform float u_min_t;
uniform int u_jitter_phase;
uniform float u_jitter_amount;
uniform int u_debug_mode;

float hash12(vec2 p) {
    vec3 p3 = fract(vec3(p.xyx) * 0.1031);
    p3 += dot(p3, p3.yzx + 33.33);
    return fract((p3.x + p3.y) * p3.z);
}

float map_sdf(vec2 p) {
    float d = 1e6;
    for (int i = 0; i < MAX_OCCLUDERS; i++) {
        if (i >= u_occluder_count) {
            break;
        }
        vec3 occ = u_occluders[i].xyz;
        float cd = length(p - occ.xy) - occ.z;
        d = min(d, cd);
    }
    return d;
}

float softshadow(vec2 ro, vec2 rd, float mint, float maxt, float w) {
    float res = 1.0;
    float ph = 1e20;
    float jitter = (hash12(ro * 0.073 + rd * 17.31 + vec2(float(u_jitter_phase) * 0.123, maxt * 0.01)) - 0.5) * u_jitter_amount;
    float t = max(0.001, mint + jitter);
    for (int i = 0; i < MAX_STEPS && t < maxt; i++) {
        float h = map_sdf(ro + rd * t);
        if (h < 0.0005) {
            return 0.0;
        }
        float y = (h * h) / max(0.0001, 2.0 * ph);
        float d2 = max(0.0, h * h - y * y);
        float d = sqrt(d2);
        float penumbra = d / max(0.0001, w * max(0.0, t - y));
        res = min(res, clamp(penumbra, 0.0, 1.0));
        ph = h;
        t += clamp(h, 0.75, 32.0);
    }
    return clamp(res, 0.0, 1.0);
}

void main() {
    vec2 rt_safe = vec2(max(1.0, u_rt_resolution.x), max(1.0, u_rt_resolution.y));
    vec2 frag = (gl_FragCoord.xy / rt_safe) * u_resolution;
    // gl_FragCoord is bottom-left origin; world/screen helpers are top-left origin.
    frag.y = u_resolution.y - frag.y;
    vec2 safe_scale = vec2(max(0.0001, u_view_scale.x), max(0.0001, u_view_scale.y));
    vec2 world = vec2(frag.x / safe_scale.x - u_camera.x, frag.y / safe_scale.y - u_camera.y);

    if (u_debug_mode == 1) {
        finalColor = vec4(0.0, 0.0, 0.0, 1.0);
        return;
    }
    if (u_debug_mode == 2) {
        float a = clamp(float(u_light_count) / float(MAX_LIGHTS), 0.0, 1.0);
        finalColor = vec4(0.0, 0.0, 0.0, a);
        return;
    }
    if (u_debug_mode == 3) {
        float a = clamp(float(u_occluder_count) / float(MAX_OCCLUDERS), 0.0, 1.0);
        finalColor = vec4(0.0, 0.0, 0.0, a);
        return;
    }
    if (u_debug_mode == 4) {
        float gx = fract((world.x + 1024.0) * 0.02);
        float gy = fract((world.y + 1024.0) * 0.02);
        finalColor = vec4(0.0, 0.0, 0.0, 0.5 * (gx + gy));
        return;
    }
    if (u_debug_mode == 5) {
        float d = abs(map_sdf(world));
        float a = clamp(1.0 - d * 0.04, 0.0, 1.0);
        finalColor = vec4(0.0, 0.0, 0.0, a);
        return;
    }
    if (u_debug_mode == 6) {
        float radius = (u_light_count > 0) ? u_lights[0].z : 0.0;
        float a = clamp(radius / 512.0, 0.0, 1.0);
        finalColor = vec4(0.0, 0.0, 0.0, a);
        return;
    }
    if (u_debug_mode == 7) {
        float radius = (u_occluder_count > 0) ? u_occluders[0].z : 0.0;
        float a = clamp(radius / 256.0, 0.0, 1.0);
        finalColor = vec4(0.0, 0.0, 0.0, a);
        return;
    }

    float visibility = 0.0;
    for (int i = 0; i < MAX_LIGHTS; i++) {
        if (i >= u_light_count) {
            break;
        }
        vec4 light = u_lights[i];
        vec4 light_dir = u_light_dirs[i];
        vec2 to_light = light.xy - world;
        float dist = length(to_light);
        if (dist <= 0.0001) {
            continue;
        }
        float effective_radius = max(1.0, light.z);
        float directional = 1.0;
        float focus = clamp(light_dir.z, 0.0, 2.0);
        if (focus > 0.0001 && dot(light_dir.xy, light_dir.xy) > 0.0001) {
            vec2 out_dir = normalize(light_dir.xy);
            vec2 from_light = world - light.xy;
            vec2 from_light_dir = from_light / max(0.0001, length(from_light));
            float alignment = dot(out_dir, from_light_dir);
            float lobe = smoothstep(-0.35, 1.0, alignment);
            float focus_mix = min(1.0, focus);
            float focus_shape = 1.0 + max(0.0, focus - 1.0) * 2.0;
            directional = max(0.05, mix(1.0, pow(lobe, 1.25 * focus_shape), focus_mix));
            float stretch = max(1.0, light_dir.w);
            effective_radius *= mix(1.0, mix(1.0, stretch, lobe), focus_mix);
        }
        if (dist >= effective_radius) {
            continue;
        }
        vec2 dir = to_light / dist;
        float shadow = softshadow(world, dir, u_min_t, dist, u_light_size_w);
        float x = clamp(1.0 - dist / max(1.0, effective_radius), 0.0, 1.0);
        float attenuation = sqrt(x) * directional;
        float lit = clamp(shadow * attenuation * light.w * u_shadow_strength, 0.0, 1.0);
        // Saturating accumulation keeps overlap smooth and avoids harsh clipping.
        visibility = 1.0 - (1.0 - visibility) * (1.0 - lit);
    }

    float darkness = clamp(u_ambient_darkness * (1.0 - visibility), 0.0, 1.0);
    finalColor = vec4(0.0, 0.0, 0.0, darkness);
}
""" % (MAX_OCCLUDERS, MAX_LIGHTS, MAX_STEPS)

_TEMPORAL_BLEND_FS_330 = """
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;

uniform sampler2D texture0;
uniform sampler2D u_current_tex;
uniform float u_response;

void main() {
    vec4 prev = texture(texture0, fragTexCoord);
    vec4 curr = texture(u_current_tex, fragTexCoord);
    float response = clamp(u_response, 0.0, 1.0);
    float darkness = mix(prev.a, curr.a, response);
    finalColor = vec4(0.0, 0.0, 0.0, darkness);
}
"""


def _is_finite_vec2(pos: Vec2) -> bool:
    return math.isfinite(float(pos.x)) and math.isfinite(float(pos.y))


def _clampf(value: float, minimum: float, maximum: float) -> float:
    return max(float(minimum), min(float(maximum), float(value)))


def _normalized_dir_from_angle(angle: float) -> tuple[float, float]:
    if not math.isfinite(float(angle)):
        return 0.0, 0.0
    vec = Vec2.from_heading(float(angle))
    length = vec.length()
    if length <= 1e-6:
        return 0.0, 0.0
    inv = 1.0 / float(length)
    return float(vec.x) * inv, float(vec.y) * inv


def _normalized_dir_from_vec(vec: Vec2 | None) -> tuple[float, float]:
    if vec is None or not _is_finite_vec2(vec):
        return 0.0, 0.0
    length = float(vec.length())
    if length <= 1e-6:
        return 0.0, 0.0
    inv = 1.0 / length
    return float(vec.x) * inv, float(vec.y) * inv


def _shadow_occluder_radius(size: float, hitbox_size: float) -> float:
    blended = max(float(hitbox_size), float(size) * 0.35)
    return max(6.0, min(128.0, float(blended)))


def collect_shadow_occluders(
    player: Any,
    creatures: list[Any],
    *,
    max_occluders: int = MAX_OCCLUDERS,
) -> list[CircleOccluder]:
    occluders: list[CircleOccluder] = []

    def _append(pos: Vec2 | None, radius: float) -> None:
        if len(occluders) >= int(max_occluders):
            return
        if pos is None:
            return
        if not _is_finite_vec2(pos):
            return
        radius_f = float(radius)
        if not math.isfinite(radius_f) or radius_f <= 0.0:
            return
        occluders.append(CircleOccluder(pos=Vec2(float(pos.x), float(pos.y)), radius=radius_f))

    if player is not None and float(getattr(player, "health", 0.0)) > 0.0:
        player_pos = getattr(player, "pos", None)
        player_size = float(getattr(player, "size", 48.0))
        player_hitbox = float(getattr(player, "size", 48.0)) * 0.4
        _append(player_pos, _shadow_occluder_radius(player_size, player_hitbox))

    for creature in creatures:
        if len(occluders) >= int(max_occluders):
            break
        if not bool(getattr(creature, "active", False)):
            continue
        if float(getattr(creature, "hp", 0.0)) <= 0.0:
            continue
        hitbox_size = float(getattr(creature, "hitbox_size", 0.0))
        if hitbox_size <= 0.0:
            continue
        size = float(getattr(creature, "size", 0.0))
        _append(getattr(creature, "pos", None), _shadow_occluder_radius(size, hitbox_size))

    return occluders


def _projectile_light(
    entry: Any,
    *,
    range_scale: float = DEFAULT_SHADOW_RANGE_SCALE,
    directional_focus: float = DEFAULT_DIRECTIONAL_FOCUS,
    directional_stretch: float = DEFAULT_DIRECTIONAL_STRETCH,
) -> ShadowLight | None:
    if not bool(getattr(entry, "active", False)):
        return None
    type_id = int(getattr(entry, "type_id", -1))
    spec = _PRIMARY_PROJECTILE_LIGHTS.get(type_id)
    if spec is None:
        return None
    pos = getattr(entry, "pos", None)
    if pos is None:
        return None
    if not _is_finite_vec2(pos):
        return None
    radius, strength = spec
    base_focus, base_stretch = _PRIMARY_PROJECTILE_DIRECTIONAL.get(type_id, (0.0, 1.0))
    dir_x, dir_y = _normalized_dir_from_angle(float(getattr(entry, "angle", 0.0)))
    focus = _clampf(float(base_focus) * float(directional_focus), 0.0, 2.0)
    stretch = _clampf(float(base_stretch) * float(directional_stretch), 1.0, 6.0)
    if abs(dir_x) <= 1e-6 and abs(dir_y) <= 1e-6:
        focus = 0.0
        stretch = 1.0
    scaled_radius = min(900.0, float(radius) * float(range_scale))
    return ShadowLight(
        pos=Vec2(float(pos.x), float(pos.y)),
        radius=scaled_radius,
        strength=float(strength),
        dir_x=float(dir_x),
        dir_y=float(dir_y),
        focus=float(focus),
        stretch=float(stretch),
    )


def _secondary_projectile_light(
    entry: Any,
    *,
    range_scale: float = DEFAULT_SHADOW_RANGE_SCALE,
    directional_focus: float = DEFAULT_DIRECTIONAL_FOCUS,
    directional_stretch: float = DEFAULT_DIRECTIONAL_STRETCH,
) -> ShadowLight | None:
    if not bool(getattr(entry, "active", False)):
        return None
    type_id = int(getattr(entry, "type_id", -1))
    spec = _SECONDARY_PROJECTILE_LIGHTS.get(type_id)
    if spec is None:
        return None
    pos = getattr(entry, "pos", None)
    if pos is None:
        return None
    if not _is_finite_vec2(pos):
        return None
    radius, strength = spec
    if type_id == int(SecondaryProjectileTypeId.DETONATION):
        radius *= max(0.5, float(getattr(entry, "detonation_scale", 1.0)))
    base_focus, base_stretch = _SECONDARY_PROJECTILE_DIRECTIONAL.get(type_id, (0.0, 1.0))
    dir_x, dir_y = _normalized_dir_from_vec(getattr(entry, "vel", None))
    if abs(dir_x) <= 1e-6 and abs(dir_y) <= 1e-6:
        dir_x, dir_y = _normalized_dir_from_angle(float(getattr(entry, "angle", 0.0)))
    focus = _clampf(float(base_focus) * float(directional_focus), 0.0, 2.0)
    stretch = _clampf(float(base_stretch) * float(directional_stretch), 1.0, 6.0)
    if abs(dir_x) <= 1e-6 and abs(dir_y) <= 1e-6:
        focus = 0.0
        stretch = 1.0
    scaled_radius = min(900.0, float(radius) * float(range_scale))
    return ShadowLight(
        pos=Vec2(float(pos.x), float(pos.y)),
        radius=scaled_radius,
        strength=float(strength),
        dir_x=float(dir_x),
        dir_y=float(dir_y),
        focus=float(focus),
        stretch=float(stretch),
    )


def transient_light_strength(light: TransientLight) -> float:
    ttl = max(1e-6, float(light.ttl))
    fade = max(0.0, 1.0 - float(light.age) / ttl)
    return max(0.0, float(light.strength) * fade)


def tick_transient_lights(lights: list[TransientLight], dt: float) -> list[TransientLight]:
    if dt <= 0.0:
        return list(lights)
    next_lights: list[TransientLight] = []
    for light in lights:
        age = float(light.age) + float(dt)
        if age >= float(light.ttl):
            continue
        next_lights.append(replace(light, age=age))
    return next_lights


def collect_shadow_lights(
    projectiles: list[Any],
    secondary_projectiles: list[Any],
    transient_lights: list[TransientLight],
    *,
    max_lights: int = MAX_LIGHTS,
    range_scale: float = DEFAULT_SHADOW_RANGE_SCALE,
    directional_focus: float = DEFAULT_DIRECTIONAL_FOCUS,
    directional_stretch: float = DEFAULT_DIRECTIONAL_STRETCH,
) -> list[ShadowLight]:
    lights: list[ShadowLight] = []
    cap = max(0, int(max_lights))
    if cap <= 0:
        return lights

    for transient in transient_lights:
        if len(lights) >= cap:
            return lights
        if not _is_finite_vec2(transient.pos):
            continue
        strength = transient_light_strength(transient)
        if strength <= 0.0:
            continue
        radius = float(transient.radius)
        if radius <= 0.0:
            continue
        scaled_radius = min(900.0, radius * float(range_scale))
        lights.append(ShadowLight(pos=transient.pos, radius=scaled_radius, strength=strength))

    for entry in projectiles:
        if len(lights) >= cap:
            return lights
        light = _projectile_light(
            entry,
            range_scale=range_scale,
            directional_focus=directional_focus,
            directional_stretch=directional_stretch,
        )
        if light is not None:
            lights.append(light)

    for entry in secondary_projectiles:
        if len(lights) >= cap:
            return lights
        light = _secondary_projectile_light(
            entry,
            range_scale=range_scale,
            directional_focus=directional_focus,
            directional_stretch=directional_stretch,
        )
        if light is not None:
            lights.append(light)

    return lights


def _shader_location(shader: rl.Shader, name: str) -> int:
    location = int(rl.get_shader_location(shader, name))
    if location < 0 and "[" not in name:
        location = int(rl.get_shader_location(shader, f"{name}[0]"))
    return int(location)


def _shader_array_locations(shader: rl.Shader, name: str, count: int) -> tuple[int, ...]:
    locations: list[int] = []
    for i in range(max(0, int(count))):
        location = int(rl.get_shader_location(shader, f"{name}[{i}]"))
        if location < 0 and i == 0:
            location = int(rl.get_shader_location(shader, name))
        locations.append(int(location))
    return tuple(locations)


def _shader_valid(shader: rl.Shader | None) -> bool:
    if shader is None:
        return False
    return int(getattr(shader, "id", 0)) > 0


def _render_texture_valid(rt: rl.RenderTexture | None) -> bool:
    if rt is None:
        return False
    if int(getattr(rt, "id", 0)) <= 0:
        return False
    validator = getattr(rl, "is_render_texture_valid", None)
    if callable(validator):
        try:
            return bool(validator(rt))
        except (RuntimeError, ValueError):
            return False
    return True


def _shadow_debug_mode_name(mode: int) -> str:
    index = int(mode)
    if 0 <= index < len(SHADOW_DEBUG_MODE_NAMES):
        return SHADOW_DEBUG_MODE_NAMES[index]
    return f"mode{index}"


class LightingDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._audio: AudioState | None = None
        self._audio_rng: random.Random | None = None
        self._console: ConsoleState | None = None

        self._world = GameWorld(
            assets_dir=ctx.assets_dir,
            world_size=WORLD_SIZE,
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
            preserve_bugs=bool(ctx.preserve_bugs),
        )
        self._player = self._world.players[0] if self._world.players else None
        self._aim_texture: rl.Texture | None = None

        # Default to Ion Rifle so the first manual shot demonstrates shadows clearly.
        self._profile_index = 1
        self._spawn_preset_index = 0
        self._auto_emit_enabled = False
        self._auto_emit_timer = 0.0
        self._transient_lights: list[TransientLight] = []

        self._shadow_enabled = True
        self._show_debug_overlays = True
        self._show_help = True
        self._shadow_debug_mode = 0
        self._shadow_warning: str | None = None
        self._shadow_shader: rl.Shader | None = None
        self._shadow_uniforms: _ShadowUniforms | None = None
        self._temporal_shader: rl.Shader | None = None
        self._temporal_uniforms: _TemporalUniforms | None = None
        self._shadow_rt: rl.RenderTexture | None = None
        self._shadow_accum_rt: rl.RenderTexture | None = None
        self._shadow_accum_swap_rt: rl.RenderTexture | None = None
        self._shadow_accum_ready = False
        self._shadow_rt_size = (0, 0)
        self._last_shadow_camera = Vec2(0.0, 0.0)
        self._last_shadow_view_scale = Vec2(1.0, 1.0)
        self._last_shadow_resolution = Vec2(1.0, 1.0)
        self._last_shadow_rt_resolution = Vec2(1.0, 1.0)
        self._shadow_output_rt_for_preview: rl.RenderTexture | None = None
        self._shadow_frame_index = 0

        self._light_size_w = float(DEFAULT_LIGHT_SIZE_W)
        self._shadow_strength = float(DEFAULT_SHADOW_STRENGTH)
        self._ambient_darkness = float(DEFAULT_AMBIENT_DARKNESS)
        self._min_t = float(DEFAULT_MIN_T)
        self._range_scale = float(DEFAULT_SHADOW_RANGE_SCALE)
        self._directional_focus = float(DEFAULT_DIRECTIONAL_FOCUS)
        self._directional_stretch = float(DEFAULT_DIRECTIONAL_STRETCH)
        self._temporal_response = float(DEFAULT_TEMPORAL_RESPONSE)
        self._jitter_amount = float(DEFAULT_JITTER_AMOUNT)
        self._shadow_rt_scale = float(SHADOW_RT_SCALE)
        self._show_tuning_panel = True
        self._tune_param_index = 0

        self._last_occluders: list[CircleOccluder] = []
        self._last_lights: list[ShadowLight] = []

        self._autodiag_enabled, self._autodiag_total_frames = self._autodiag_config_from_env()
        self._autodiag_frame = 0
        self._autodiag_next_emit_frame = 0
        self._autodiag_segment = -1
        self._autodiag_started = False

        self._dump_all_modes_enabled = self._bool_env(DUMP_ALL_MODES_ENV)
        self._dump_mode_sequence: tuple[int, ...] = tuple(range(len(SHADOW_DEBUG_MODE_NAMES)))
        self._dump_mode_index = 0
        self._dump_mode_frame = 0
        self._dump_mode_emitter_timer = 0
        self._dump_modes_started = False

        self.close_requested = False
        self._paused = False
        self._screenshot_requested = False

    @staticmethod
    def _autodiag_config_from_env() -> tuple[bool, int]:
        raw = os.getenv(AUTODIAG_ENV)
        if raw is None or raw.strip() == "":
            return False, 0
        value = raw.strip().lower()
        if value in {"0", "false", "off", "no"}:
            return False, 0
        if value in {"1", "true", "on", "yes"}:
            return True, AUTODIAG_FRAMES_DEFAULT
        try:
            frames = int(value)
        except ValueError:
            frames = AUTODIAG_FRAMES_DEFAULT
        return True, max(30, frames)

    @staticmethod
    def _bool_env(name: str) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return False
        value = raw.strip().lower()
        if value in {"", "0", "false", "off", "no"}:
            return False
        return value in {"1", "true", "on", "yes"}

    def _set_shadow_debug_mode(self, mode: int) -> None:
        next_mode = int(mode) % len(SHADOW_DEBUG_MODE_NAMES)
        if next_mode == self._shadow_debug_mode:
            return
        self._shadow_debug_mode = next_mode
        # Debug mode switches should never blend history from a previous mode.
        self._invalidate_shadow_history()

    def _selected_tune_param(self) -> _TuneParam:
        return _TUNE_PARAMS[self._tune_param_index % len(_TUNE_PARAMS)]

    @staticmethod
    def _tune_attr_name(key: str) -> str:
        if key == "rt_scale":
            return "_shadow_rt_scale"
        return f"_{key}"

    def _get_tune_value(self, key: str) -> float:
        return float(getattr(self, self._tune_attr_name(key)))

    def _invalidate_shadow_history(self) -> None:
        self._shadow_accum_ready = False
        self._shadow_output_rt_for_preview = self._shadow_rt

    def _set_tune_value(self, key: str, value: float, *, invalidate_history: bool = True) -> None:
        current = float(self._get_tune_value(key))
        if math.isclose(current, float(value), rel_tol=0.0, abs_tol=1e-6):
            return
        setattr(self, self._tune_attr_name(key), float(value))
        if invalidate_history:
            self._invalidate_shadow_history()

    def _reset_tuning_defaults(self) -> None:
        for key, default in _TUNE_DEFAULTS.items():
            self._set_tune_value(key, default, invalidate_history=key != "rt_scale")
        self._invalidate_shadow_history()

    def _adjust_selected_tune(self, direction: int) -> None:
        if direction == 0:
            return
        param = self._selected_tune_param()
        shift_down = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
        step = float(param.coarse_step if shift_down else param.step)
        next_value = _clampf(
            self._get_tune_value(param.key) + float(direction) * step,
            param.minimum,
            param.maximum,
        )
        self._set_tune_value(param.key, next_value, invalidate_history=param.key != "rt_scale")
        if param.key == "shadow_rt_scale":
            self._shadow_rt_size = (0, 0)
            self._invalidate_shadow_history()

    def _run_autodiag(self) -> None:
        if self._dump_all_modes_enabled:
            self._run_dump_all_modes()
            return
        if not self._autodiag_enabled:
            return

        if not self._autodiag_started:
            self._autodiag_started = True
            self._shadow_enabled = True
            self._show_debug_overlays = True
            self._show_help = False
            self._paused = False
            self._auto_emit_enabled = False
            self._spawn_preset_ring()
            print(
                "[lighting-debug] autodiag start "
                f"frames={self._autodiag_total_frames} seg={AUTODIAG_SEGMENT_FRAMES}"
            )

        segment = max(0, self._autodiag_frame // AUTODIAG_SEGMENT_FRAMES)
        if segment != self._autodiag_segment:
            self._autodiag_segment = segment
            self._profile_index = segment % len(EMISSIVE_PROFILES)
            self._spawn_preset_index = segment % len(SPAWN_PRESETS)
            self._spawn_preset_ring()
            mode = AUTODIAG_DEBUG_MODE_SEQUENCE[segment % len(AUTODIAG_DEBUG_MODE_SEQUENCE)]
            self._set_shadow_debug_mode(mode)
            self._screenshot_requested = True
            print(
                "[lighting-debug] autodiag segment "
                f"{segment} frame={self._autodiag_frame} "
                f"profile={self._selected_profile().name} "
                f"mode={self._shadow_debug_mode}({_shadow_debug_mode_name(self._shadow_debug_mode)})"
            )

        if self._autodiag_frame >= self._autodiag_next_emit_frame:
            self._autodiag_next_emit_frame = self._autodiag_frame + 7
            self._emit_profile()

        self._autodiag_frame += 1
        if self._autodiag_frame >= self._autodiag_total_frames:
            self._screenshot_requested = True
            self.close_requested = True
            print(f"[lighting-debug] autodiag done frame={self._autodiag_frame}")

    def _run_dump_all_modes(self) -> None:
        if not self._dump_all_modes_enabled:
            return
        if not self._dump_mode_sequence:
            self.close_requested = True
            return

        if not self._dump_modes_started:
            self._dump_modes_started = True
            self._shadow_enabled = True
            self._show_debug_overlays = True
            self._show_help = False
            self._show_tuning_panel = False
            self._paused = False
            self._auto_emit_enabled = False
            self._set_tune_value("temporal_response", 1.0)
            self._reset_scene()
            self._profile_index = 1
            self._spawn_preset_index = 0
            print(
                "[lighting-debug] dump-all start "
                f"modes={','.join(str(mode) for mode in self._dump_mode_sequence)} "
                f"settle={DUMP_ALL_SETTLE_FRAMES}"
            )

        self._dump_mode_emitter_timer += 1
        if self._dump_mode_emitter_timer >= DUMP_ALL_EMIT_INTERVAL:
            self._dump_mode_emitter_timer = 0
            self._emit_profile()

        mode = int(self._dump_mode_sequence[self._dump_mode_index])
        if self._shadow_debug_mode != mode:
            self._set_shadow_debug_mode(mode)

        self._dump_mode_frame += 1
        if self._dump_mode_frame == DUMP_ALL_SETTLE_FRAMES:
            self._screenshot_requested = True
            print(f"[lighting-debug] dump-all capture mode={mode} ({_shadow_debug_mode_name(mode)})")
            return
        if self._dump_mode_frame < DUMP_ALL_SETTLE_FRAMES:
            return

        self._dump_mode_frame = 0
        self._dump_mode_index += 1
        if self._dump_mode_index >= len(self._dump_mode_sequence):
            self._screenshot_requested = True
            self.close_requested = True
            print("[lighting-debug] dump-all done")

    def _shadow_rt_alpha_stats(self) -> tuple[int, float, int] | None:
        rt = self._shadow_rt
        if rt is None or not _render_texture_valid(rt):
            return None
        image = rl.load_image_from_texture(rt.texture)
        try:
            width = max(1, int(image.width))
            height = max(1, int(image.height))
            step_x = max(1, width // 64)
            step_y = max(1, height // 64)
            count = 0
            total = 0.0
            min_alpha = 255
            max_alpha = 0
            for y in range(0, height, step_y):
                for x in range(0, width, step_x):
                    alpha = int(rl.get_image_color(image, x, y).a)
                    min_alpha = min(min_alpha, alpha)
                    max_alpha = max(max_alpha, alpha)
                    total += float(alpha)
                    count += 1
            if count <= 0:
                return None
            return min_alpha, total / float(count), max_alpha
        finally:
            rl.unload_image(image)

    def _autodiag_log_shadow_stats(self) -> None:
        if not self._autodiag_enabled:
            return
        if self._autodiag_frame <= 0:
            return
        frame = self._autodiag_frame
        if frame % AUTODIAG_LOG_INTERVAL != 0 and frame != self._autodiag_total_frames:
            return
        stats = self._shadow_rt_alpha_stats()
        if stats is None:
            print(f"[lighting-debug] frame={frame} alpha=unavailable")
            return
        min_alpha, avg_alpha, max_alpha = stats
        print(
            "[lighting-debug] frame="
            f"{frame} mode={self._shadow_debug_mode}({_shadow_debug_mode_name(self._shadow_debug_mode)}) "
            f"occ={len(self._last_occluders)} lights={len(self._last_lights)} "
            f"cam=({self._last_shadow_camera.x:.2f},{self._last_shadow_camera.y:.2f}) "
            f"scale=({self._last_shadow_view_scale.x:.4f},{self._last_shadow_view_scale.y:.4f}) "
            f"res=({self._last_shadow_resolution.x:.0f},{self._last_shadow_resolution.y:.0f}) "
            f"rt=({self._last_shadow_rt_resolution.x:.0f},{self._last_shadow_rt_resolution.y:.0f}) "
            f"alpha(min/avg/max)=({min_alpha},{avg_alpha:.1f},{max_alpha})"
        )

    def _selected_profile(self) -> EmissiveProfile:
        return EMISSIVE_PROFILES[self._profile_index % len(EMISSIVE_PROFILES)]

    def _selected_spawn_preset(self) -> SpawnPreset:
        return SPAWN_PRESETS[self._spawn_preset_index % len(SPAWN_PRESETS)]

    def _apply_debug_player_cheats(self) -> None:
        if self._player is None:
            return
        self._player.speed_multiplier = float(PLAYER_SPEED_MULTIPLIER)
        self._player.shield_timer = float(PLAYER_INVULNERABLE_SHIELD_TIMER)

    def _clear_scene_contents(self) -> None:
        self._world.creatures.reset()
        self._world.state.projectiles.reset()
        self._world.state.secondary_projectiles.reset()
        self._world.state.particles.reset()
        self._world.state.sprite_effects.reset()
        self._world.state.effects.reset()
        self._world.state.bonus_pool.reset()
        self._world.fx_queue.clear()
        self._world.fx_queue_rotated.clear()
        self._transient_lights.clear()
        self._invalidate_shadow_history()

    def _reset_scene(self) -> None:
        self._world.reset(seed=0xBEEF, player_count=1, spawn_pos=WORLD_CENTER)
        self._player = self._world.players[0] if self._world.players else None
        self._apply_debug_player_cheats()
        self._clear_scene_contents()
        # Seed a default occluder ring so shadows are visible immediately on first emission.
        self._spawn_preset_ring()
        self._auto_emit_timer = 0.0
        self._shadow_frame_index = 0
        self._world.update_camera(0.0)

    def _build_input(self) -> PlayerInput:
        move = Vec2(
            float(rl.is_key_down(rl.KeyboardKey.KEY_D)) - float(rl.is_key_down(rl.KeyboardKey.KEY_A)),
            float(rl.is_key_down(rl.KeyboardKey.KEY_S)) - float(rl.is_key_down(rl.KeyboardKey.KEY_W)),
        )
        mouse = rl.get_mouse_position()
        aim = self._world.screen_to_world(Vec2.from_xy(mouse))
        return PlayerInput(
            move=move,
            aim=aim,
            fire_down=False,
            fire_pressed=False,
            reload_pressed=False,
        )

    @staticmethod
    def _burst_angle(profile: EmissiveProfile, index: int) -> float:
        count = max(1, int(profile.burst_count))
        center = (float(count) - 1.0) * 0.5
        return (float(index) - center) * float(profile.spread_rad)

    def _emit_profile(self) -> None:
        player = self._player
        if player is None:
            return
        profile = self._selected_profile()

        aim_delta = player.aim - player.pos
        aim_dir, aim_len = aim_delta.normalized_with_length()
        if aim_len <= 1e-5:
            aim_dir = Vec2(1.0, 0.0)
        heading = aim_dir.to_heading()
        muzzle_pos = (player.pos + aim_dir * float(profile.spawn_distance)).clamp_rect(
            8.0, 8.0, WORLD_SIZE - 8.0, WORLD_SIZE - 8.0
        )

        if profile.secondary_type_id == int(SecondaryProjectileTypeId.DETONATION):
            impact = (player.pos + aim_dir * float(profile.explosion_distance)).clamp_rect(
                16.0, 16.0, WORLD_SIZE - 16.0, WORLD_SIZE - 16.0
            )
            self._world.state.secondary_projectiles.spawn(
                pos=impact,
                angle=float(heading),
                type_id=int(SecondaryProjectileTypeId.DETONATION),
                owner_id=-100,
                time_to_live=float(profile.secondary_ttl),
            )
            self._push_transient_light(
                impact,
                radius=float(profile.flash_radius),
                ttl=float(profile.flash_ttl),
                strength=float(profile.flash_strength),
            )
            self._push_transient_light(
                muzzle_pos,
                radius=max(80.0, float(profile.flash_radius) * 0.4),
                ttl=max(0.08, float(profile.flash_ttl) * 0.7),
                strength=max(0.5, float(profile.flash_strength) * 0.65),
            )
            return

        count = max(1, int(profile.burst_count))
        for i in range(count):
            angle = float(heading) + self._burst_angle(profile, i)
            if profile.primary_type_id is not None:
                self._world.state.projectiles.spawn(
                    pos=muzzle_pos,
                    angle=angle,
                    type_id=int(profile.primary_type_id),
                    owner_id=-100,
                )
            if profile.secondary_type_id is not None:
                self._world.state.secondary_projectiles.spawn(
                    pos=muzzle_pos,
                    angle=angle,
                    type_id=int(profile.secondary_type_id),
                    owner_id=-100,
                    time_to_live=float(profile.secondary_ttl),
                    creatures=self._world.creatures.entries,
                    target_hint=player.aim,
                )

        self._push_transient_light(
            muzzle_pos,
            radius=float(profile.flash_radius),
            ttl=float(profile.flash_ttl),
            strength=float(profile.flash_strength),
        )

    def _push_transient_light(self, pos: Vec2, *, radius: float, ttl: float, strength: float) -> None:
        light = TransientLight(
            pos=Vec2(float(pos.x), float(pos.y)),
            radius=max(1.0, float(radius)),
            strength=max(0.0, float(strength)),
            ttl=max(1e-3, float(ttl)),
            age=0.0,
        )
        self._transient_lights.append(light)
        if len(self._transient_lights) > 64:
            self._transient_lights = self._transient_lights[-64:]

    def _spawn_preset_ring(self) -> None:
        player = self._player
        if player is None:
            return
        preset = self._selected_spawn_preset()
        count = max(1, int(preset.ring_count))
        for idx in range(count):
            angle = float(idx) / float(count) * math.tau
            pos = (player.pos + Vec2.from_angle(angle) * ENEMY_RING_RADIUS).clamp_rect(
                48.0, 48.0, WORLD_SIZE - 48.0, WORLD_SIZE - 48.0
            )
            heading = angle + math.pi
            self._world.creatures.spawn_template(
                int(preset.spawn_id),
                pos,
                heading,
                self._world.state.rng,
                rand=self._world.state.rng.rand,
            )

    def _clear_spawned_enemies(self) -> None:
        self._world.creatures.reset()

    def _handle_debug_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._paused = not self._paused
        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._show_help = not self._show_help
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
            self._shadow_enabled = not self._shadow_enabled
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
            self._show_debug_overlays = not self._show_debug_overlays
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F4):
            self._auto_emit_enabled = not self._auto_emit_enabled
            self._auto_emit_timer = 0.0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F6):
            self._set_shadow_debug_mode(self._shadow_debug_mode + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F7):
            self._reset_tuning_defaults()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F8):
            self._show_tuning_panel = not self._show_tuning_panel

        if rl.is_key_pressed(rl.KeyboardKey.KEY_T):
            self._tune_param_index = (self._tune_param_index + 1) % len(_TUNE_PARAMS)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_MINUS):
            self._adjust_selected_tune(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_EQUAL):
            self._adjust_selected_tune(+1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ZERO):
            param = self._selected_tune_param()
            default = _TUNE_DEFAULTS.get(param.key)
            if default is not None:
                self._set_tune_value(param.key, default, invalidate_history=param.key != "rt_scale")
                if param.key == "rt_scale":
                    self._shadow_rt_size = (0, 0)
                    self._invalidate_shadow_history()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._profile_index = (self._profile_index - 1) % len(EMISSIVE_PROFILES)
            self._auto_emit_timer = 0.0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._profile_index = (self._profile_index + 1) % len(EMISSIVE_PROFILES)
            self._auto_emit_timer = 0.0

        if rl.is_key_pressed(rl.KeyboardKey.KEY_COMMA):
            self._spawn_preset_index = (self._spawn_preset_index - 1) % len(SPAWN_PRESETS)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PERIOD):
            self._spawn_preset_index = (self._spawn_preset_index + 1) % len(SPAWN_PRESETS)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
            self._spawn_preset_ring()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_M):
            self._clear_spawned_enemies()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            self._reset_scene()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True

        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._emit_profile()

    def _update_auto_emit(self, dt: float) -> None:
        if not self._auto_emit_enabled or dt <= 0.0:
            return
        profile = self._selected_profile()
        interval = self._profile_auto_interval(profile)
        self._auto_emit_timer += float(dt)
        budget = 8
        while self._auto_emit_timer >= interval and budget > 0:
            self._auto_emit_timer -= interval
            self._emit_profile()
            budget -= 1
        if budget <= 0:
            self._auto_emit_timer = 0.0

    @staticmethod
    def _profile_auto_interval(profile: EmissiveProfile) -> float:
        weapon_id = profile.rate_weapon_id
        if weapon_id is not None:
            entry = WEAPON_BY_ID.get(int(weapon_id))
            cooldown = None if entry is None else entry.shot_cooldown
            if cooldown is not None:
                return max(0.001, float(cooldown))
        return max(0.001, float(profile.auto_interval))

    def _collect_shadow_state(self) -> None:
        self._last_occluders = collect_shadow_occluders(
            self._player,
            self._world.creatures.entries,
            max_occluders=MAX_OCCLUDERS,
        )
        self._last_lights = collect_shadow_lights(
            self._world.state.projectiles.entries,
            self._world.state.secondary_projectiles.entries,
            self._transient_lights,
            max_lights=MAX_LIGHTS,
            range_scale=self._range_scale,
            directional_focus=self._directional_focus,
            directional_stretch=self._directional_stretch,
        )

    def open(self) -> None:
        self._missing_assets.clear()

        bootstrap = init_view_audio(self._assets_root)
        self._world.config = bootstrap.config
        self._console = bootstrap.console
        self._audio = bootstrap.audio
        self._audio_rng = bootstrap.audio_rng
        self._world.audio = self._audio
        self._world.audio_rng = self._audio_rng

        try:
            # Load after audio/bootstrap so missing PAQs can be downloaded first.
            self._small = load_small_font(self._assets_root)
        except FileNotFoundError:
            self._small = None
            self._missing_assets.append("load/smallFnt.dat + load/smallWhite.tga")

        self._world.open()
        self._aim_texture = self._world._load_texture(
            "ui_aim",
            cache_path="ui/ui_aim.jaz",
        )
        self._reset_scene()
        self._ensure_shadow_shader()
        self._ensure_shadow_rt()
        rl.hide_cursor()

    def _release_shadow_resources(self) -> None:
        for rt in (self._shadow_rt, self._shadow_accum_rt, self._shadow_accum_swap_rt):
            if rt is not None and _render_texture_valid(rt):
                rl.unload_render_texture(rt)
        self._shadow_rt = None
        self._shadow_accum_rt = None
        self._shadow_accum_swap_rt = None
        self._shadow_accum_ready = False
        self._shadow_output_rt_for_preview = None
        self._shadow_rt_size = (0, 0)

        shader = self._shadow_shader
        if shader is not None and _shader_valid(shader):
            rl.unload_shader(shader)
        self._shadow_shader = None
        self._shadow_uniforms = None

        temporal_shader = self._temporal_shader
        if temporal_shader is not None and _shader_valid(temporal_shader):
            rl.unload_shader(temporal_shader)
        self._temporal_shader = None
        self._temporal_uniforms = None

    def close(self) -> None:
        rl.show_cursor()
        self._release_shadow_resources()

        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._audio is not None:
            shutdown_audio(self._audio)
            self._audio = None
            self._audio_rng = None
            self._console = None
        self._world.audio = None
        self._world.audio_rng = None
        self._world.close()
        self._aim_texture = None

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def _ensure_shadow_shader(self) -> bool:
        if _shader_valid(self._shadow_shader) and self._shadow_uniforms is not None:
            return True

        try:
            shader = rl.load_shader_from_memory(_SHADOW_VS_330, _SHADOW_FS_330)
        except (RuntimeError, OSError, ValueError) as exc:
            self._shadow_warning = f"shadow shader init failed: {exc}"
            self._shadow_shader = None
            self._shadow_uniforms = None
            return False

        if not _shader_valid(shader):
            self._shadow_warning = "shadow shader unavailable (compile/link failed)"
            self._shadow_shader = None
            self._shadow_uniforms = None
            return False

        uniforms = _ShadowUniforms(
            resolution=_shader_location(shader, "u_resolution"),
            rt_resolution=_shader_location(shader, "u_rt_resolution"),
            camera=_shader_location(shader, "u_camera"),
            view_scale=_shader_location(shader, "u_view_scale"),
            occluder_count=_shader_location(shader, "u_occluder_count"),
            occluders=_shader_array_locations(shader, "u_occluders", MAX_OCCLUDERS),
            light_count=_shader_location(shader, "u_light_count"),
            lights=_shader_array_locations(shader, "u_lights", MAX_LIGHTS),
            light_dirs=_shader_array_locations(shader, "u_light_dirs", MAX_LIGHTS),
            light_size_w=_shader_location(shader, "u_light_size_w"),
            shadow_strength=_shader_location(shader, "u_shadow_strength"),
            ambient_darkness=_shader_location(shader, "u_ambient_darkness"),
            min_t=_shader_location(shader, "u_min_t"),
            jitter_phase=_shader_location(shader, "u_jitter_phase"),
            jitter_amount=_shader_location(shader, "u_jitter_amount"),
            debug_mode=_shader_location(shader, "u_debug_mode"),
        )
        if self._autodiag_enabled:
            print(
                "[lighting-debug] uniform locations "
                f"occ0={uniforms.occluders[0] if uniforms.occluders else -1} "
                f"occ1={uniforms.occluders[1] if len(uniforms.occluders) > 1 else -1} "
                f"light0={uniforms.lights[0] if uniforms.lights else -1} "
                f"light1={uniforms.lights[1] if len(uniforms.lights) > 1 else -1}"
            )
        missing: list[str] = []
        for name in (
            "resolution",
            "rt_resolution",
            "camera",
            "view_scale",
            "occluder_count",
            "light_count",
            "light_size_w",
            "shadow_strength",
            "ambient_darkness",
            "min_t",
            "jitter_phase",
            "jitter_amount",
            "debug_mode",
        ):
            if int(getattr(uniforms, name)) < 0:
                missing.append(name)
        if not uniforms.occluders or int(uniforms.occluders[0]) < 0:
            missing.append("occluders")
        if not uniforms.lights or int(uniforms.lights[0]) < 0:
            missing.append("lights")
        if not uniforms.light_dirs or int(uniforms.light_dirs[0]) < 0:
            missing.append("light_dirs")
        if missing:
            rl.unload_shader(shader)
            self._shadow_warning = "shadow shader missing uniforms: " + ", ".join(sorted(missing))
            self._shadow_shader = None
            self._shadow_uniforms = None
            return False

        self._shadow_shader = shader
        self._shadow_uniforms = uniforms
        self._shadow_warning = None
        return True

    def _ensure_temporal_shader(self) -> bool:
        if _shader_valid(self._temporal_shader) and self._temporal_uniforms is not None:
            return True

        try:
            shader = rl.load_shader_from_memory(_SHADOW_VS_330, _TEMPORAL_BLEND_FS_330)
        except (RuntimeError, OSError, ValueError) as exc:
            self._shadow_warning = f"shadow temporal shader init failed: {exc}"
            self._temporal_shader = None
            self._temporal_uniforms = None
            return False

        if not _shader_valid(shader):
            self._shadow_warning = "shadow temporal shader unavailable (compile/link failed)"
            self._temporal_shader = None
            self._temporal_uniforms = None
            return False

        uniforms = _TemporalUniforms(
            current_tex=_shader_location(shader, "u_current_tex"),
            response=_shader_location(shader, "u_response"),
        )
        missing: list[str] = []
        if uniforms.current_tex < 0:
            missing.append("u_current_tex")
        if uniforms.response < 0:
            missing.append("u_response")
        if missing:
            rl.unload_shader(shader)
            self._shadow_warning = "shadow temporal shader missing uniforms: " + ", ".join(missing)
            self._temporal_shader = None
            self._temporal_uniforms = None
            return False

        self._temporal_shader = shader
        self._temporal_uniforms = uniforms
        if self._shadow_warning is not None and "temporal shader" in self._shadow_warning:
            self._shadow_warning = None
        return True

    def _ensure_shadow_rt(self) -> bool:
        screen_w = max(1, int(rl.get_screen_width()))
        screen_h = max(1, int(rl.get_screen_height()))
        rt_scale = _clampf(self._shadow_rt_scale, RT_SCALE_MIN, RT_SCALE_MAX)
        rt_w = max(1, int(float(screen_w) * rt_scale))
        rt_h = max(1, int(float(screen_h) * rt_scale))
        desired = (rt_w, rt_h)

        if (
            _render_texture_valid(self._shadow_rt)
            and _render_texture_valid(self._shadow_accum_rt)
            and _render_texture_valid(self._shadow_accum_swap_rt)
            and self._shadow_rt_size == desired
        ):
            return True

        for existing_rt in (self._shadow_rt, self._shadow_accum_rt, self._shadow_accum_swap_rt):
            if existing_rt is not None and _render_texture_valid(existing_rt):
                rl.unload_render_texture(existing_rt)
        self._shadow_rt = None
        self._shadow_accum_rt = None
        self._shadow_accum_swap_rt = None
        self._shadow_accum_ready = False
        self._shadow_output_rt_for_preview = None
        self._shadow_rt_size = (0, 0)

        rt: rl.RenderTexture | None = None
        accum: rl.RenderTexture | None = None
        accum_swap: rl.RenderTexture | None = None
        try:
            rt = rl.load_render_texture(rt_w, rt_h)
            accum = rl.load_render_texture(rt_w, rt_h)
            accum_swap = rl.load_render_texture(rt_w, rt_h)
        except (RuntimeError, OSError, ValueError) as exc:
            for maybe_rt in (rt, accum, accum_swap):
                if maybe_rt is not None and _render_texture_valid(maybe_rt):
                    rl.unload_render_texture(maybe_rt)
            self._shadow_warning = f"shadow render target init failed: {exc}"
            return False

        assert rt is not None
        assert accum is not None
        assert accum_swap is not None
        if not _render_texture_valid(rt) or not _render_texture_valid(accum) or not _render_texture_valid(accum_swap):
            if _render_texture_valid(rt):
                rl.unload_render_texture(rt)
            if _render_texture_valid(accum):
                rl.unload_render_texture(accum)
            if _render_texture_valid(accum_swap):
                rl.unload_render_texture(accum_swap)
            self._shadow_warning = "shadow render target unavailable"
            return False

        rl.set_texture_filter(rt.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        rl.set_texture_filter(accum.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        rl.set_texture_filter(accum_swap.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        self._shadow_rt = rt
        self._shadow_accum_rt = accum
        self._shadow_accum_swap_rt = accum_swap
        self._shadow_accum_ready = False
        self._shadow_output_rt_for_preview = rt
        self._shadow_rt_size = desired
        if self._shadow_warning is not None and "render target" in self._shadow_warning:
            self._shadow_warning = None
        return True

    def _set_shadow_uniforms(
        self,
        *,
        occluders: list[CircleOccluder],
        lights: list[ShadowLight],
    ) -> None:
        assert self._shadow_shader is not None
        assert self._shadow_uniforms is not None
        assert self._shadow_rt is not None

        uniforms = self._shadow_uniforms
        shader = self._shadow_shader

        camera, view_scale = self._world.renderer._world_params()
        rt_w, rt_h = self._shadow_rt_size
        screen_w = max(1.0, float(rl.get_screen_width()))
        screen_h = max(1.0, float(rl.get_screen_height()))
        self._last_shadow_camera = Vec2(float(camera.x), float(camera.y))
        self._last_shadow_view_scale = Vec2(float(view_scale.x), float(view_scale.y))
        self._last_shadow_resolution = Vec2(float(screen_w), float(screen_h))
        self._last_shadow_rt_resolution = Vec2(float(rt_w), float(rt_h))

        rl.set_shader_value(
            shader,
            int(uniforms.resolution),
            # World reconstruction must use full-screen pixel space.
            # The pass itself still runs at low-res RT via normalized UVs.
            rl.ffi.new("Vector2 *", {"x": screen_w, "y": screen_h}),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.rt_resolution),
            rl.ffi.new("Vector2 *", {"x": float(rt_w), "y": float(rt_h)}),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.camera),
            rl.ffi.new("Vector2 *", {"x": float(camera.x), "y": float(camera.y)}),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.view_scale),
            rl.ffi.new("Vector2 *", {"x": float(view_scale.x), "y": float(view_scale.y)}),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        )

        light_count = min(len(lights), MAX_LIGHTS)
        occluder_count = min(len(occluders), MAX_OCCLUDERS)

        rl.set_shader_value(
            shader,
            int(uniforms.occluder_count),
            rl.ffi.new("int *", int(occluder_count)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.light_count),
            rl.ffi.new("int *", int(light_count)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.light_size_w),
            rl.ffi.new("float *", float(self._light_size_w)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.shadow_strength),
            rl.ffi.new("float *", float(self._shadow_strength)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.ambient_darkness),
            rl.ffi.new("float *", float(self._ambient_darkness)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.min_t),
            rl.ffi.new("float *", float(self._min_t)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.jitter_phase),
            rl.ffi.new("int *", int(self._shadow_frame_index)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.jitter_amount),
            rl.ffi.new("float *", float(self._jitter_amount)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
        )
        rl.set_shader_value(
            shader,
            int(uniforms.debug_mode),
            rl.ffi.new("int *", int(self._shadow_debug_mode)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )

        occ_data = rl.ffi.new("Vector4[]", int(MAX_OCCLUDERS))
        for i in range(occluder_count):
            occ = occluders[i]
            occ_data[i].x = float(occ.pos.x)
            occ_data[i].y = float(occ.pos.y)
            occ_data[i].z = float(occ.radius)
            occ_data[i].w = 1.0
        occ_loc = int(uniforms.occluders[0]) if uniforms.occluders else -1
        if occ_loc >= 0:
            occ_ptr = rl.ffi.cast("Vector4 *", occ_data)
            rl.set_shader_value_v(
                shader,
                occ_loc,
                occ_ptr,
                rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
                int(MAX_OCCLUDERS),
            )

        light_data = rl.ffi.new("Vector4[]", int(MAX_LIGHTS))
        light_dir_data = rl.ffi.new("Vector4[]", int(MAX_LIGHTS))
        for i in range(light_count):
            light = lights[i]
            light_data[i].x = float(light.pos.x)
            light_data[i].y = float(light.pos.y)
            light_data[i].z = float(light.radius)
            light_data[i].w = float(light.strength)
            light_dir_data[i].x = float(light.dir_x)
            light_dir_data[i].y = float(light.dir_y)
            light_dir_data[i].z = float(light.focus)
            light_dir_data[i].w = float(light.stretch)
        light_loc = int(uniforms.lights[0]) if uniforms.lights else -1
        if light_loc >= 0:
            light_ptr = rl.ffi.cast("Vector4 *", light_data)
            rl.set_shader_value_v(
                shader,
                light_loc,
                light_ptr,
                rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
                int(MAX_LIGHTS),
            )

        light_dir_loc = int(uniforms.light_dirs[0]) if uniforms.light_dirs else -1
        if light_dir_loc >= 0:
            light_dir_ptr = rl.ffi.cast("Vector4 *", light_dir_data)
            rl.set_shader_value_v(
                shader,
                light_dir_loc,
                light_dir_ptr,
                rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
                int(MAX_LIGHTS),
            )

    def _copy_shadow_rt(self, src: rl.RenderTexture, dst: rl.RenderTexture) -> None:
        rt_w, rt_h = self._shadow_rt_size
        src_rect = rl.Rectangle(0.0, 0.0, float(rt_w), -float(rt_h))
        dst_rect = rl.Rectangle(0.0, 0.0, float(rt_w), float(rt_h))
        rl.begin_texture_mode(dst)
        rl.clear_background(rl.Color(0, 0, 0, 0))
        rl.draw_texture_pro(src.texture, src_rect, dst_rect, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        rl.end_texture_mode()

    def _resolve_shadow_output_rt(self) -> rl.RenderTexture | None:
        if self._shadow_rt is None or not _render_texture_valid(self._shadow_rt):
            return None
        if self._shadow_accum_rt is None or not _render_texture_valid(self._shadow_accum_rt):
            self._shadow_output_rt_for_preview = self._shadow_rt
            return self._shadow_rt
        if self._shadow_accum_swap_rt is None or not _render_texture_valid(self._shadow_accum_swap_rt):
            self._shadow_output_rt_for_preview = self._shadow_rt
            return self._shadow_rt

        response = _clampf(self._temporal_response, 0.0, 1.0)
        if response >= 0.999:
            if self._shadow_warning is not None and "temporal shader" in self._shadow_warning:
                self._shadow_warning = None
            self._shadow_output_rt_for_preview = self._shadow_rt
            return self._shadow_rt

        if not self._ensure_temporal_shader():
            self._shadow_output_rt_for_preview = self._shadow_rt
            return self._shadow_rt

        # Keep debug modes deterministic: output should reflect the selected
        # diagnostic directly, without temporal cross-fade from mode 0.
        if self._shadow_debug_mode != 0:
            self._shadow_output_rt_for_preview = self._shadow_rt
            return self._shadow_rt

        if not self._shadow_accum_ready:
            self._copy_shadow_rt(self._shadow_rt, self._shadow_accum_rt)
            self._shadow_accum_ready = True
            self._shadow_output_rt_for_preview = self._shadow_accum_rt
            return self._shadow_accum_rt

        assert self._temporal_shader is not None
        assert self._temporal_uniforms is not None

        shader = self._temporal_shader
        uniforms = self._temporal_uniforms
        rt_w, rt_h = self._shadow_rt_size
        src_rect = rl.Rectangle(0.0, 0.0, float(rt_w), -float(rt_h))
        dst_rect = rl.Rectangle(0.0, 0.0, float(rt_w), float(rt_h))

        rl.set_shader_value(
            shader,
            int(uniforms.response),
            rl.ffi.new("float *", float(response)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
        )

        rl.begin_texture_mode(self._shadow_accum_swap_rt)
        rl.clear_background(rl.Color(0, 0, 0, 0))
        rl.begin_shader_mode(shader)
        # Bind the secondary sampler while shader mode is active; this is more stable across backends.
        rl.set_shader_value_texture(shader, int(uniforms.current_tex), self._shadow_rt.texture)
        rl.draw_texture_pro(self._shadow_accum_rt.texture, src_rect, dst_rect, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        rl.end_shader_mode()
        rl.end_texture_mode()

        self._shadow_accum_rt, self._shadow_accum_swap_rt = self._shadow_accum_swap_rt, self._shadow_accum_rt
        self._shadow_accum_ready = True
        self._shadow_output_rt_for_preview = self._shadow_accum_rt
        return self._shadow_accum_rt

    def _draw_shadow_overlay(self) -> None:
        if not self._shadow_enabled:
            self._shadow_output_rt_for_preview = None
            return
        if not self._ensure_shadow_shader():
            return
        if not self._ensure_shadow_rt():
            return
        if self._shadow_rt is None or self._shadow_shader is None:
            return

        try:
            self._set_shadow_uniforms(occluders=self._last_occluders, lights=self._last_lights)
        except (RuntimeError, ValueError, TypeError) as exc:
            self._shadow_warning = f"shadow uniform update failed: {exc}"
            return

        rt_w, rt_h = self._shadow_rt_size
        rl.begin_texture_mode(self._shadow_rt)
        rl.clear_background(rl.Color(0, 0, 0, 0))
        rl.begin_shader_mode(self._shadow_shader)
        rl.draw_rectangle(0, 0, rt_w, rt_h, rl.WHITE)
        rl.end_shader_mode()
        rl.end_texture_mode()
        self._shadow_frame_index = (self._shadow_frame_index + 1) & 0x7FFFFFFF
        self._autodiag_log_shadow_stats()

        output_rt = self._resolve_shadow_output_rt()
        if output_rt is None:
            output_rt = self._shadow_rt
        if output_rt is None:
            return
        src = rl.Rectangle(0.0, 0.0, float(rt_w), -float(rt_h))
        dst = rl.Rectangle(0.0, 0.0, float(rl.get_screen_width()), float(rl.get_screen_height()))
        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
        rl.draw_texture_pro(output_rt.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        rl.end_blend_mode()

    def update(self, dt: float) -> None:
        self._player = self._world.players[0] if self._world.players else None
        self._handle_debug_input()
        self._run_autodiag()

        sim_dt = float(dt)
        if self._paused:
            sim_dt = 0.0

        if self._player is not None:
            self._apply_debug_player_cheats()
            self._update_auto_emit(sim_dt)
            self._world.update(
                sim_dt,
                inputs=[self._build_input()],
                game_mode=int(GameMode.SURVIVAL),
            )
        elif self._world.players:
            self._player = self._world.players[0]

        self._transient_lights = tick_transient_lights(self._transient_lights, sim_dt)
        self._collect_shadow_state()

        if self._audio is not None:
            update_audio(self._audio, sim_dt)

    def _world_scale(self) -> float:
        _camera, view_scale = self._world.renderer._world_params()
        return view_scale.avg_component()

    def _draw_shadow_debug_geometry(self) -> None:
        scale = self._world_scale()
        for occluder in self._last_occluders:
            screen = self._world.world_to_screen(occluder.pos)
            radius = max(1.0, float(occluder.radius) * scale)
            rl.draw_circle_lines(int(screen.x), int(screen.y), int(radius), OCCLUDER_COLOR)

        for light in self._last_lights:
            screen = self._world.world_to_screen(light.pos)
            radius = max(1.0, float(light.radius) * scale)
            rl.draw_circle_lines(int(screen.x), int(screen.y), int(radius), LIGHT_RING_COLOR)
            rl.draw_circle(int(screen.x), int(screen.y), 2.0, LIGHT_CORE_COLOR)
            if float(light.focus) > 0.01 and (abs(float(light.dir_x)) > 1e-4 or abs(float(light.dir_y)) > 1e-4):
                dir_len = max(16.0, radius * 0.28 * float(light.stretch))
                tip_x = screen.x + float(light.dir_x) * dir_len
                tip_y = screen.y + float(light.dir_y) * dir_len
                rl.draw_line_ex(
                    rl.Vector2(float(screen.x), float(screen.y)),
                    rl.Vector2(float(tip_x), float(tip_y)),
                    2.0,
                    LIGHT_CORE_COLOR,
                )

    def _draw_shadow_preview(self) -> None:
        if not self._show_debug_overlays:
            return
        preview_rt = self._shadow_output_rt_for_preview
        if preview_rt is None or not _render_texture_valid(preview_rt):
            preview_rt = self._shadow_rt
        if preview_rt is None or not _render_texture_valid(preview_rt):
            return

        rt_w, rt_h = self._shadow_rt_size
        if rt_w <= 0 or rt_h <= 0:
            return

        screen_w = float(rl.get_screen_width())
        pad = 6.0
        margin = 12.0
        title_h = 12.0 if self._small is not None else 0.0

        content_w = 240.0
        content_h = content_w * (float(rt_h) / float(rt_w))
        max_h = 156.0
        if content_h > max_h:
            scale = max_h / content_h
            content_h *= scale
            content_w *= scale

        panel_w = content_w + pad * 2.0
        panel_h = content_h + pad * 2.0 + title_h
        x = screen_w - panel_w - margin
        y = margin

        rl.draw_rectangle(int(x), int(y), int(panel_w), int(panel_h), SHADOW_PREVIEW_BG)
        rl.draw_rectangle_lines(int(x), int(y), int(panel_w), int(panel_h), SHADOW_PREVIEW_BORDER)

        if self._small is not None:
            draw_ui_text(self._small, "shadow map", Vec2(x + pad, y + 1.0), color=SHADOW_PREVIEW_TEXT)

        map_x = x + pad
        map_y = y + pad + title_h
        rl.draw_rectangle(int(map_x), int(map_y), int(content_w), int(content_h), SHADOW_PREVIEW_CANVAS)

        src = rl.Rectangle(0.0, 0.0, float(rt_w), -float(rt_h))
        dst = rl.Rectangle(map_x, map_y, content_w, content_h)
        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
        rl.draw_texture_pro(preview_rt.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        rl.end_blend_mode()

    def _draw_tuning_panel(self) -> None:
        if not self._show_tuning_panel:
            return

        line = float(ui_line_height(self._small))
        pad = 6.0
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        panel_w = 338.0
        panel_h = (len(_TUNE_PARAMS) + 2) * line + pad * 2.0
        x = screen_w - panel_w - 12.0
        y = 186.0 if self._show_debug_overlays else 12.0
        y = min(y, max(12.0, screen_h - panel_h - 12.0))

        rl.draw_rectangle(int(x), int(y), int(panel_w), int(panel_h), SHADOW_PREVIEW_BG)
        rl.draw_rectangle_lines(int(x), int(y), int(panel_w), int(panel_h), SHADOW_PREVIEW_BORDER)

        draw_ui_text(
            self._small,
            "tuning (T select, -/= adjust, shift coarse, 0 reset, F7 defaults)",
            Vec2(x + pad, y + 1.0),
            color=SHADOW_PREVIEW_TEXT,
        )
        y += line
        selected = self._selected_tune_param()
        draw_ui_text(self._small, f"selected: {selected.label}", Vec2(x + pad, y + 1.0), color=UI_HINT)
        y += line

        for idx, param in enumerate(_TUNE_PARAMS):
            value = self._get_tune_value(param.key)
            marker = ">" if idx == self._tune_param_index else " "
            draw_ui_text(
                self._small,
                f"{marker} {param.label:16s} {value:6.3f}",
                Vec2(x + pad, y + 1.0),
                color=UI_TEXT if idx == self._tune_param_index else UI_HINT,
            )
            y += line

    def _draw_overlay_ui(self) -> None:
        x = 16.0
        y = 12.0
        line = float(ui_line_height(self._small))

        profile = self._selected_profile()
        preset = self._selected_spawn_preset()
        creatures_alive = sum(1 for creature in self._world.creatures.entries if creature.active and creature.hp > 0.0)
        primary_count = sum(1 for entry in self._world.state.projectiles.entries if entry.active)
        secondary_count = sum(1 for entry in self._world.state.secondary_projectiles.entries if entry.active)

        draw_ui_text(self._small, "Lighting debug: 2D SDF soft shadows", Vec2(x, y), color=UI_TEXT)
        y += line
        draw_ui_text(
            self._small,
            f"profile {self._profile_index + 1}/{len(EMISSIVE_PROFILES)}: {profile.name}  auto {'on' if self._auto_emit_enabled else 'off'} ({self._profile_auto_interval(profile):.3f}s)",
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        draw_ui_text(
            self._small,
            f"spawn preset {self._spawn_preset_index + 1}/{len(SPAWN_PRESETS)}: {preset.name}",
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        draw_ui_text(
            self._small,
            f"occluders {len(self._last_occluders)}/{MAX_OCCLUDERS}  lights {len(self._last_lights)}/{MAX_LIGHTS}",
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        draw_ui_text(
            self._small,
            f"creatures {creatures_alive}  primary {primary_count}  secondary {secondary_count}",
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        draw_ui_text(
            self._small,
            f"shadows {'on' if self._shadow_enabled else 'off'}  overlays {'on' if self._show_debug_overlays else 'off'}  paused {'yes' if self._paused else 'no'}",
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        draw_ui_text(
            self._small,
            (
                f"ambient {self._ambient_darkness:.2f}  reveal {self._shadow_strength:.2f}  "
                f"light_w {self._light_size_w:.2f}  min_t {self._min_t:.1f}  range {self._range_scale:.2f}"
            ),
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        draw_ui_text(
            self._small,
            (
                f"dir focus {self._directional_focus:.2f} stretch {self._directional_stretch:.2f}  "
                f"jitter {self._jitter_amount:.2f}  temporal {self._temporal_response:.2f}  rt {self._shadow_rt_scale:.2f}"
            ),
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        draw_ui_text(
            self._small,
            "note: only player + creature hitboxes cast shadows in this pass",
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(
            self._small,
            f"shader debug {self._shadow_debug_mode}: {_shadow_debug_mode_name(self._shadow_debug_mode)}",
            Vec2(x, y),
            color=UI_TEXT,
        )

        warn_x = 16.0
        warn_y = float(rl.get_screen_height()) - line * 3.0
        if self._shadow_warning is not None and self._shadow_enabled:
            draw_ui_text(self._small, f"shadow warning: {self._shadow_warning}", Vec2(warn_x, warn_y), color=UI_WARNING)

        if not self._show_help:
            self._draw_tuning_panel()
            return

        y = float(rl.get_screen_height()) - line * 5.0
        draw_ui_text(
            self._small,
            "WASD move  LMB emit  [/] projectile profile  F4 auto emit",
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(
            self._small,
            ",/. spawn preset  N spawn ring  M clear enemies  Backspace reset scene",
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(
            self._small,
            "F2 shadows  F3 overlays  F6 shader dbg  F7 tune defaults  F8 tuning panel",
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(
            self._small,
            "T select tune  -/= adjust  Shift coarse  0 reset tune  H help  Space pause  P screenshot  Esc quit",
            Vec2(x, y),
            color=UI_HINT,
        )

        self._draw_tuning_panel()

    def draw(self) -> None:
        rl.clear_background(BG)
        self._world.draw(draw_aim_indicators=True)
        self._draw_shadow_overlay()

        if self._show_debug_overlays:
            self._draw_shadow_debug_geometry()
            self._draw_shadow_preview()
        self._draw_overlay_ui()

        if self._missing_assets:
            draw_ui_text(
                self._small,
                "Missing assets: " + ", ".join(self._missing_assets),
                Vec2(16.0, 16.0),
                color=UI_ERROR,
            )

        mouse = rl.get_mouse_position()
        draw_aim_cursor(self._world.particles_texture, self._aim_texture, pos=Vec2.from_xy(mouse))


@register_view("lighting-debug", "Lighting debug")
def build_lighting_debug_view(ctx: ViewContext) -> View:
    return LightingDebugView(ctx)
