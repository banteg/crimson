from __future__ import annotations

import math
import os
import time
from typing import TYPE_CHECKING

import msgspec

from grim.app import RunViewHooks
from grim.assets import TextureId
from grim.audio import AudioState, shutdown_audio, update_audio
from grim.console import ConsoleState
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

from ..creatures.spawn import SpawnId
from ..game_modes import GameMode
from ..owner_ref import OwnerRef
from ..projectiles.runtime import SecondarySpawnSpec
from ..projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from ..sim.input import PlayerInput
from ..sim.input_providers import FrameContext, LocalInputRuntime
from ..tooling.audio_bootstrap import init_view_audio
from ..ui.cursor import draw_aim_cursor
from ..weapons import WEAPON_BY_ID, WeaponId
from ..world import WorldRuntime
from ..world.standalone_tick_harness import StandaloneTickHarness
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import ViewInstance, register_view

if TYPE_CHECKING:
    from ..creatures.runtime import CreatureState
    from ..projectiles.types import Projectile, SecondaryProjectile
    from ..sim.state_types import PlayerState

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
LIGHT_SELECTED_COLOR = rl.Color(255, 255, 120, 255)
LIGHT_HANDLE_MOVE = rl.Color(120, 220, 255, 255)
LIGHT_HANDLE_RADIUS = rl.Color(255, 200, 90, 255)
LIGHT_HANDLE_DIR = rl.Color(255, 245, 185, 255)
LIGHT_HANDLE_STRENGTH = rl.Color(255, 130, 170, 255)
LIGHT_HANDLE_STRETCH = rl.Color(130, 255, 170, 255)
SHADOW_PREVIEW_BG = rl.Color(14, 14, 18, 220)
SHADOW_PREVIEW_BORDER = rl.Color(90, 90, 110, 240)
SHADOW_PREVIEW_CANVAS = rl.Color(176, 176, 176, 255)
SHADOW_PREVIEW_TEXT = rl.Color(215, 215, 215, 255)

SHADOW_RT_SCALE = 0.30
MAX_LIGHTS = 6
MAX_OCCLUDERS = 20
MAX_STEPS = 56

DEFAULT_LIGHT_SIZE_W = 0.33
DEFAULT_SHADOW_STRENGTH = 1.01
DEFAULT_MIN_T = 2.6
DEFAULT_SHADOW_RANGE_SCALE = 1.52
DEFAULT_AMBIENT_DARKNESS = 0.76
DEFAULT_DIRECTIONAL_FOCUS = 1.12
DEFAULT_DIRECTIONAL_STRETCH = 1.22
# Keep temporal accumulation off by default; some backends/drivers produce stale
# blends with the secondary sampler path and hide shadows entirely.
DEFAULT_TEMPORAL_RESPONSE = 1.00
DEFAULT_JITTER_AMOUNT = 0.78

RT_SCALE_MIN = 0.15
RT_SCALE_MAX = 0.75

PLAYER_SPEED_MULTIPLIER = 4.0
PLAYER_INVULNERABLE_SHIELD_TIMER = 1e-3
ENEMY_RING_RADIUS = 280.0
STATIC_LIGHT_RADIUS_MIN = 24.0
STATIC_LIGHT_RADIUS_MAX = 900.0
STATIC_LIGHT_STRENGTH_MIN = 0.05
STATIC_LIGHT_STRENGTH_MAX = 2.25
STATIC_LIGHT_FOCUS_MIN = 0.0
STATIC_LIGHT_FOCUS_MAX = 2.0
STATIC_LIGHT_STRETCH_MIN = 1.0
STATIC_LIGHT_STRETCH_MAX = 4.0

STATIC_HANDLE_HIT_RADIUS_PX = 14.0
STATIC_HANDLE_DRAW_RADIUS_PX = 6.0

AUTODIAG_ENV = "CRIMSON_LIGHTING_DEBUG_AUTODIAG"
AUTODIAG_FRAMES_DEFAULT = 300
AUTODIAG_SEGMENT_FRAMES = 50
AUTODIAG_LOG_INTERVAL = 15
DUMP_ALL_MODES_ENV = "CRIMSON_LIGHTING_DEBUG_DUMP_ALL_MODES"
DUMP_ALL_SETTLE_FRAMES = 12
DUMP_ALL_EMIT_INTERVAL = 6
AUTO_TUNE_ENV = "CRIMSON_LIGHTING_DEBUG_AUTO_TUNE"
AUTO_TUNE_SAMPLE_FRAMES_DEFAULT = 96
AUTO_TUNE_WARMUP_FRAMES = 28
AUTO_TUNE_METRIC_GRID = 84
AUTO_TUNE_TARGET_SHADOW_MS = 2.8

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


class CircleOccluder(msgspec.Struct, frozen=True):
    pos: Vec2
    radius: float


class ShadowLight(msgspec.Struct, frozen=True):
    pos: Vec2
    radius: float
    strength: float
    dir_x: float = 0.0
    dir_y: float = 0.0
    focus: float = 0.0
    stretch: float = 1.0


class TransientLight(msgspec.Struct, frozen=True):
    pos: Vec2
    radius: float
    strength: float
    ttl: float
    age: float = 0.0


class EmissiveProfile(msgspec.Struct, frozen=True):
    name: str
    auto_interval: float
    rate_weapon_id: int | None = None
    primary_type_id: ProjectileTemplateId | None = None
    secondary_type_id: SecondaryProjectileTypeId | None = None
    burst_count: int = 1
    spread_rad: float = 0.0
    spawn_distance: float = 28.0
    secondary_ttl: float = 2.0
    flash_radius: float = 120.0
    flash_ttl: float = 0.2
    flash_strength: float = 1.0
    explosion_distance: float = 110.0


class SpawnPreset(msgspec.Struct, frozen=True):
    name: str
    spawn_id: SpawnId
    ring_count: int = 10


class StaticEmitter(msgspec.Struct):
    pos: Vec2
    angle: float
    radius: float
    strength: float
    focus: float
    stretch: float


class _StaticDragState(msgspec.Struct):
    kind: str
    emitter_index: int
    mouse_start_world: Vec2
    mouse_start_screen: Vec2
    pos_offset: Vec2
    value_start: float


class _ShadowUniforms(msgspec.Struct, frozen=True):
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


class _TemporalUniforms(msgspec.Struct, frozen=True):
    current_tex: int
    response: int


class _TuneParam(msgspec.Struct, frozen=True):
    key: str
    label: str
    minimum: float
    maximum: float
    step: float
    coarse_step: float


class _AutoTunePreset(msgspec.Struct, frozen=True):
    name: str
    ambient_darkness: float
    shadow_strength: float
    light_size_w: float
    min_t: float
    range_scale: float
    directional_focus: float
    directional_stretch: float
    jitter_amount: float
    temporal_response: float
    rt_scale: float

    def as_tune_values(self) -> dict[str, float]:
        return {
            "ambient_darkness": float(self.ambient_darkness),
            "shadow_strength": float(self.shadow_strength),
            "light_size_w": float(self.light_size_w),
            "min_t": float(self.min_t),
            "range_scale": float(self.range_scale),
            "directional_focus": float(self.directional_focus),
            "directional_stretch": float(self.directional_stretch),
            "jitter_amount": float(self.jitter_amount),
            "temporal_response": float(self.temporal_response),
            "rt_scale": float(self.rt_scale),
        }


class _ShadowFrameMetrics(msgspec.Struct, frozen=True):
    mean_alpha: float
    std_alpha: float
    contrast: float
    coverage: float
    banding: float


class _AutoTuneAccumulator(msgspec.Struct):
    sample_count: int = 0
    flicker_count: int = 0
    shadow_ms_sum: float = 0.0
    mean_sum: float = 0.0
    std_sum: float = 0.0
    contrast_sum: float = 0.0
    coverage_sum: float = 0.0
    banding_sum: float = 0.0
    flicker_sum: float = 0.0


class _AutoTuneResult(msgspec.Struct, frozen=True):
    preset: _AutoTunePreset
    score: float
    shadow_ms: float
    mean_alpha: float
    std_alpha: float
    contrast: float
    coverage: float
    banding: float
    flicker: float


EMISSIVE_PROFILES: tuple[EmissiveProfile, ...] = (
    EmissiveProfile(
        name="Muzzle",
        auto_interval=0.11,
        rate_weapon_id=WeaponId.PISTOL,
        primary_type_id=ProjectileTemplateId.PISTOL,
        flash_radius=95.0,
        flash_ttl=0.11,
        flash_strength=1.0,
    ),
    EmissiveProfile(
        name="Ion Rifle",
        auto_interval=0.16,
        rate_weapon_id=WeaponId.ION_RIFLE,
        primary_type_id=ProjectileTemplateId.ION_RIFLE,
        flash_radius=140.0,
        flash_ttl=0.17,
        flash_strength=1.0,
    ),
    EmissiveProfile(
        name="Ion Minigun",
        auto_interval=0.06,
        rate_weapon_id=WeaponId.ION_MINIGUN,
        primary_type_id=ProjectileTemplateId.ION_MINIGUN,
        burst_count=2,
        spread_rad=0.03,
        flash_radius=135.0,
        flash_ttl=0.12,
        flash_strength=0.9,
    ),
    EmissiveProfile(
        name="Plasma Rifle",
        auto_interval=0.13,
        rate_weapon_id=WeaponId.PLASMA_RIFLE,
        primary_type_id=ProjectileTemplateId.PLASMA_RIFLE,
        flash_radius=150.0,
        flash_ttl=0.19,
        flash_strength=1.0,
    ),
    EmissiveProfile(
        name="Plasma Cannon",
        auto_interval=0.27,
        rate_weapon_id=WeaponId.PLASMA_CANNON,
        primary_type_id=ProjectileTemplateId.PLASMA_CANNON,
        flash_radius=210.0,
        flash_ttl=0.24,
        flash_strength=1.0,
    ),
    EmissiveProfile(
        name="Fire/Flame",
        auto_interval=0.08,
        rate_weapon_id=WeaponId.HR_FLAMER,
        primary_type_id=ProjectileTemplateId.FIRE_BULLETS,
        burst_count=4,
        spread_rad=0.16,
        flash_radius=125.0,
        flash_ttl=0.16,
        flash_strength=0.9,
    ),
    EmissiveProfile(
        name="Explosion",
        auto_interval=0.45,
        rate_weapon_id=WeaponId.ROCKET_LAUNCHER,
        secondary_type_id=SecondaryProjectileTypeId.DETONATION,
        secondary_ttl=0.95,
        flash_radius=280.0,
        flash_ttl=0.3,
        flash_strength=1.0,
        spawn_distance=8.0,
        explosion_distance=120.0,
    ),
)


SPAWN_PRESETS: tuple[SpawnPreset, ...] = (
    SpawnPreset(name="Zombie Small White", spawn_id=SpawnId.ZOMBIE_SMALL_WHITE_42, ring_count=12),
    SpawnPreset(name="Zombie Brute", spawn_id=SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43, ring_count=10),
    SpawnPreset(name="Lizard", spawn_id=SpawnId.LIZARD_CONST_GREY_2F, ring_count=10),
    SpawnPreset(name="Lizard Boss", spawn_id=SpawnId.LIZARD_CONST_YELLOW_BOSS_30, ring_count=8),
    SpawnPreset(name="Alien", spawn_id=SpawnId.ALIEN_CONST_GREEN_24, ring_count=10),
    SpawnPreset(name="Alien Big Gray", spawn_id=SpawnId.ALIEN_BIG_GRAY_29, ring_count=9),
    SpawnPreset(name="Spider Small Blue", spawn_id=SpawnId.SPIDER_SMALL_BLUE_40, ring_count=11),
    SpawnPreset(name="Spider SP2", spawn_id=SpawnId.SPIDER_SP2_RANDOM_35, ring_count=11),
)

STATIC_OCCLUDER_LAYOUT: tuple[tuple[float, float, float], ...] = (
    (286.0, 246.0, 50.0),
    (460.0, 222.0, 44.0),
    (630.0, 252.0, 58.0),
    (760.0, 398.0, 64.0),
    (690.0, 564.0, 52.0),
    (510.0, 610.0, 70.0),
    (342.0, 536.0, 56.0),
    (258.0, 392.0, 48.0),
    (518.0, 404.0, 80.0),
)


_PRIMARY_PROJECTILE_LIGHTS: dict[int, tuple[float, float]] = {
    ProjectileTemplateId.PISTOL: (105.0, 0.75),
    ProjectileTemplateId.ION_RIFLE: (235.0, 1.0),
    ProjectileTemplateId.ION_MINIGUN: (190.0, 0.95),
    ProjectileTemplateId.PLASMA_RIFLE: (220.0, 1.0),
    ProjectileTemplateId.PLASMA_CANNON: (275.0, 1.0),
    ProjectileTemplateId.FIRE_BULLETS: (170.0, 0.9),
}

_SECONDARY_PROJECTILE_LIGHTS: dict[int, tuple[float, float]] = {
    SecondaryProjectileTypeId.ROCKET: (230.0, 0.95),
    SecondaryProjectileTypeId.HOMING_ROCKET: (245.0, 1.0),
    SecondaryProjectileTypeId.DETONATION: (280.0, 1.0),
    SecondaryProjectileTypeId.ROCKET_MINIGUN: (180.0, 0.85),
}

_PRIMARY_PROJECTILE_DIRECTIONAL: dict[int, tuple[float, float]] = {
    ProjectileTemplateId.PISTOL: (0.20, 1.15),
    # Ion streak emissive is rendered head->tail and is not forward-cone biased.
    ProjectileTemplateId.ION_RIFLE: (0.0, 1.0),
    ProjectileTemplateId.ION_MINIGUN: (0.0, 1.0),
    # Plasma glow is omni in the native render path (head + aura/tail sprites).
    ProjectileTemplateId.PLASMA_RIFLE: (0.0, 1.0),
    ProjectileTemplateId.PLASMA_CANNON: (0.0, 1.0),
    ProjectileTemplateId.FIRE_BULLETS: (0.55, 1.45),
}

_SECONDARY_PROJECTILE_DIRECTIONAL: dict[int, tuple[float, float]] = {
    SecondaryProjectileTypeId.ROCKET: (0.80, 2.00),
    SecondaryProjectileTypeId.HOMING_ROCKET: (0.86, 2.20),
    SecondaryProjectileTypeId.DETONATION: (0.0, 1.0),
    SecondaryProjectileTypeId.ROCKET_MINIGUN: (0.72, 1.80),
}

_ION_PROJECTILE_TYPES: frozenset[int] = frozenset(
    {
        ProjectileTemplateId.ION_RIFLE.value,
        ProjectileTemplateId.ION_MINIGUN.value,
    },
)

_OMNI_PROJECTILE_TYPES: frozenset[int] = frozenset(
    {
        ProjectileTemplateId.ION_RIFLE.value,
        ProjectileTemplateId.ION_MINIGUN.value,
        ProjectileTemplateId.PLASMA_RIFLE.value,
        ProjectileTemplateId.PLASMA_CANNON.value,
    },
)

# Ion beam visual pass draws only the last 256 units of streak; mirror that for tail lighting.
_ION_TAIL_MAX_LENGTH = 256.0
_ION_TAIL_SAMPLES: tuple[tuple[float, float, float], ...] = (
    # (distance factor from head, strength factor, radius factor)
    (0.36, 0.52, 0.88),
    (0.74, 0.30, 0.68),
)

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

_AUTO_TUNE_PRESETS: tuple[_AutoTunePreset, ...] = (
    _AutoTunePreset(
        name="baseline",
        ambient_darkness=0.78,
        shadow_strength=1.02,
        light_size_w=0.30,
        min_t=3.0,
        range_scale=1.55,
        directional_focus=1.15,
        directional_stretch=1.25,
        jitter_amount=1.00,
        temporal_response=1.00,
        rt_scale=0.25,
    ),
    _AutoTunePreset(
        name="balanced_smooth",
        ambient_darkness=0.75,
        shadow_strength=1.00,
        light_size_w=0.34,
        min_t=2.5,
        range_scale=1.58,
        directional_focus=1.10,
        directional_stretch=1.22,
        jitter_amount=0.65,
        temporal_response=1.00,
        rt_scale=0.30,
    ),
    _AutoTunePreset(
        name="quality_soft",
        ambient_darkness=0.72,
        shadow_strength=0.98,
        light_size_w=0.36,
        min_t=2.2,
        range_scale=1.62,
        directional_focus=1.05,
        directional_stretch=1.20,
        jitter_amount=0.60,
        temporal_response=1.00,
        rt_scale=0.33,
    ),
    _AutoTunePreset(
        name="perf_balanced",
        ambient_darkness=0.76,
        shadow_strength=1.01,
        light_size_w=0.33,
        min_t=2.6,
        range_scale=1.52,
        directional_focus=1.12,
        directional_stretch=1.22,
        jitter_amount=0.78,
        temporal_response=1.00,
        rt_scale=0.30,
    ),
    _AutoTunePreset(
        name="long_penumbra",
        ambient_darkness=0.74,
        shadow_strength=0.98,
        light_size_w=0.39,
        min_t=2.0,
        range_scale=1.68,
        directional_focus=1.00,
        directional_stretch=1.16,
        jitter_amount=0.55,
        temporal_response=1.00,
        rt_scale=0.36,
    ),
    _AutoTunePreset(
        name="perf_safe",
        ambient_darkness=0.77,
        shadow_strength=1.00,
        light_size_w=0.32,
        min_t=2.9,
        range_scale=1.50,
        directional_focus=1.10,
        directional_stretch=1.20,
        jitter_amount=0.82,
        temporal_response=1.00,
        rt_scale=0.28,
    ),
)

_AUTO_TUNE_STATIC_EMITTERS: tuple[tuple[float, float, float, float, float, float, float], ...] = (
    # (x, y, angle, radius, strength, focus, stretch)
    (386.0, 286.0, 0.45, 240.0, 1.00, 0.0, 1.0),
    (596.0, 322.0, 2.70, 215.0, 0.96, 1.20, 1.40),
    (522.0, 552.0, -1.25, 286.0, 1.04, 0.28, 1.10),
    (730.0, 486.0, -2.55, 206.0, 0.90, 1.45, 1.70),
)

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
""" % (MAX_OCCLUDERS, MAX_LIGHTS, MAX_STEPS)  # noqa: UP031 - GLSL braces make str.format error-prone

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


def _screen_distance_sq(a: Vec2, b: Vec2) -> float:
    dx = float(a.x) - float(b.x)
    dy = float(a.y) - float(b.y)
    return dx * dx + dy * dy


def _shadow_frame_metrics(alpha_values: list[int], sample_w: int, sample_h: int) -> _ShadowFrameMetrics | None:
    count = len(alpha_values)
    if count <= 0:
        return None
    if int(sample_w) <= 0 or int(sample_h) <= 0:
        return None
    if int(sample_w) * int(sample_h) != count:
        return None

    total = 0.0
    min_alpha = 255
    max_alpha = 0
    covered = 0
    for value in alpha_values:
        alpha = max(0, min(255, int(value)))
        total += float(alpha)
        min_alpha = min(min_alpha, alpha)
        max_alpha = max(max_alpha, alpha)
        if 6 <= alpha <= 245:
            covered += 1

    mean = total / float(count)
    variance = 0.0
    for value in alpha_values:
        diff = float(int(value)) - mean
        variance += diff * diff
    variance /= float(count)
    std = math.sqrt(max(0.0, variance))

    transitions = 0
    flat = 0
    hard = 0
    width = int(sample_w)
    height = int(sample_h)
    for y in range(height):
        row = y * width
        for x in range(width):
            idx = row + x
            if x + 1 < width:
                diff = abs(int(alpha_values[idx]) - int(alpha_values[idx + 1]))
                transitions += 1
                if diff <= 2:
                    flat += 1
                if diff >= 16:
                    hard += 1
            if y + 1 < height:
                diff = abs(int(alpha_values[idx]) - int(alpha_values[idx + width]))
                transitions += 1
                if diff <= 2:
                    flat += 1
                if diff >= 16:
                    hard += 1

    transition_denom = float(max(1, transitions))
    flat_ratio = float(flat) / transition_denom
    hard_ratio = float(hard) / transition_denom
    banding = _clampf(flat_ratio * hard_ratio * 4.0, 0.0, 1.0)

    return _ShadowFrameMetrics(
        mean_alpha=float(mean),
        std_alpha=float(std),
        contrast=_clampf(float(max_alpha - min_alpha) / 255.0, 0.0, 1.0),
        coverage=_clampf(float(covered) / float(count), 0.0, 1.0),
        banding=float(banding),
    )


def _shadow_quality_score(
    metrics: _ShadowFrameMetrics,
    *,
    shadow_ms: float,
    flicker: float,
    target_shadow_ms: float = AUTO_TUNE_TARGET_SHADOW_MS,
) -> float:
    mean_normalized = _clampf(float(metrics.mean_alpha) / 255.0, 0.0, 1.0)
    mean_target = 0.58
    mean_score = 1.0 - _clampf(abs(mean_normalized - mean_target) / 0.45, 0.0, 1.0)
    spread_score = _clampf((float(metrics.std_alpha) / 255.0) / 0.32, 0.0, 1.0)
    contrast_score = _clampf(float(metrics.contrast) / 0.70, 0.0, 1.0)
    coverage_score = 1.0 - _clampf(abs(float(metrics.coverage) - 0.58) / 0.58, 0.0, 1.0)
    banding_score = 1.0 - _clampf(float(metrics.banding) / 0.12, 0.0, 1.0)
    flicker_score = 1.0 - _clampf((float(flicker) / 255.0) / 0.18, 0.0, 1.0)
    perf_score = _clampf(float(target_shadow_ms) / max(1e-3, float(shadow_ms)), 0.0, 1.0)

    score = (
        0.05 * mean_score
        + 0.15 * spread_score
        + 0.08 * contrast_score
        + 0.05 * coverage_score
        + 0.40 * banding_score
        + 0.07 * flicker_score
        + 0.20 * perf_score
    )
    return _clampf(float(score), 0.0, 1.0)


def _auto_tune_selection_score(result: _AutoTuneResult) -> float:
    score = float(result.score)
    # Prefer smoother penumbras over raw contrast/brightness if quality scores are close.
    score += (0.15 - float(result.banding)) * 0.9
    if float(result.contrast) < 0.50:
        score -= (0.50 - float(result.contrast)) * 0.7
    return float(score)


def _profile_light_defaults(profile: EmissiveProfile) -> tuple[float, float, float, float]:
    if profile.primary_type_id is not None:
        type_id = int(profile.primary_type_id)
        spec = _PRIMARY_PROJECTILE_LIGHTS.get(type_id)
        if spec is not None:
            radius, strength = spec
            focus, stretch = _PRIMARY_PROJECTILE_DIRECTIONAL.get(type_id, (0.0, 1.0))
            return float(radius), float(strength), float(focus), float(stretch)
    if profile.secondary_type_id is not None:
        type_id = int(profile.secondary_type_id)
        spec = _SECONDARY_PROJECTILE_LIGHTS.get(type_id)
        if spec is not None:
            radius, strength = spec
            focus, stretch = _SECONDARY_PROJECTILE_DIRECTIONAL.get(type_id, (0.0, 1.0))
            return float(radius), float(strength), float(focus), float(stretch)
    return float(profile.flash_radius), float(profile.flash_strength), 0.0, 1.0


def _build_static_occluders() -> list[CircleOccluder]:
    occluders: list[CircleOccluder] = []
    for x, y, radius in STATIC_OCCLUDER_LAYOUT:
        occluders.append(CircleOccluder(pos=Vec2(float(x), float(y)), radius=float(radius)))
    return occluders


def _shadow_occluder_radius(size: float, lifecycle_stage: float) -> float:
    blended = max(float(lifecycle_stage), float(size) * 0.35)
    return max(6.0, min(128.0, float(blended)))


def collect_shadow_occluders(
    player: PlayerState | None,
    creatures: list[CreatureState],
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

    if player is not None and float(player.health) > 0.0:
        player_size = float(player.size)
        player_hitbox = float(player.size) * 0.4
        _append(player.pos, _shadow_occluder_radius(player_size, player_hitbox))

    for creature in creatures:
        if len(occluders) >= int(max_occluders):
            break
        if not creature.active:
            continue
        if float(creature.hp) <= 0.0:
            continue
        lifecycle_stage = float(creature.lifecycle_stage)
        if lifecycle_stage <= 0.0:
            continue
        size = float(creature.size)
        _append(creature.pos, _shadow_occluder_radius(size, lifecycle_stage))

    return occluders


def _projectile_lights(
    entry: Projectile,
    *,
    range_scale: float = DEFAULT_SHADOW_RANGE_SCALE,
    directional_focus: float = DEFAULT_DIRECTIONAL_FOCUS,
    directional_stretch: float = DEFAULT_DIRECTIONAL_STRETCH,
) -> tuple[ShadowLight, ...]:
    if not entry.active:
        return ()
    type_id = int(entry.type_id)
    spec = _PRIMARY_PROJECTILE_LIGHTS.get(type_id)
    if spec is None:
        return ()
    pos = entry.pos
    if pos is None:
        return ()
    if not _is_finite_vec2(pos):
        return ()
    radius, strength = spec
    base_focus, base_stretch = _PRIMARY_PROJECTILE_DIRECTIONAL.get(type_id, (0.0, 1.0))
    dir_x, dir_y = _normalized_dir_from_angle(float(entry.angle))
    focus = _clampf(float(base_focus) * float(directional_focus), 0.0, 2.0)
    stretch = _clampf(float(base_stretch) * float(directional_stretch), 1.0, 6.0)
    if type_id in _OMNI_PROJECTILE_TYPES or (abs(dir_x) <= 1e-6 and abs(dir_y) <= 1e-6):
        dir_x = 0.0
        dir_y = 0.0
        focus = 0.0
        stretch = 1.0
    scaled_radius = min(900.0, float(radius) * float(range_scale))
    head = ShadowLight(
        pos=Vec2(float(pos.x), float(pos.y)),
        radius=scaled_radius,
        strength=float(strength),
        dir_x=float(dir_x),
        dir_y=float(dir_y),
        focus=float(focus),
        stretch=float(stretch),
    )

    if type_id not in _ION_PROJECTILE_TYPES:
        return (head,)

    origin = entry.origin
    if origin is None or not _is_finite_vec2(origin):
        return (head,)

    tail_vec = pos - origin
    tail_dir, tail_dist = tail_vec.normalized_with_length()
    if tail_dist <= 1e-4:
        return (head,)

    tail_len = min(float(tail_dist), _ION_TAIL_MAX_LENGTH)
    lights = [head]
    for dist_factor, strength_factor, radius_factor in _ION_TAIL_SAMPLES:
        sample = pos - tail_dir * (tail_len * float(dist_factor))
        if not _is_finite_vec2(sample):
            continue
        sample_strength = float(strength) * float(strength_factor)
        sample_radius = max(1.0, float(scaled_radius) * float(radius_factor))
        if sample_strength <= 0.0 or sample_radius <= 0.0:
            continue
        lights.append(
            ShadowLight(
                pos=Vec2(float(sample.x), float(sample.y)),
                radius=sample_radius,
                strength=sample_strength,
            ),
        )
    return tuple(lights)


def _secondary_projectile_light(
    entry: SecondaryProjectile,
    *,
    range_scale: float = DEFAULT_SHADOW_RANGE_SCALE,
    directional_focus: float = DEFAULT_DIRECTIONAL_FOCUS,
    directional_stretch: float = DEFAULT_DIRECTIONAL_STRETCH,
) -> ShadowLight | None:
    if not entry.active:
        return None
    type_id = int(entry.type_id)
    spec = _SECONDARY_PROJECTILE_LIGHTS.get(type_id)
    if spec is None:
        return None
    pos = entry.pos
    if pos is None:
        return None
    if not _is_finite_vec2(pos):
        return None
    radius, strength = spec
    if type_id == int(SecondaryProjectileTypeId.DETONATION):
        radius *= max(0.5, float(entry.detonation_scale))
    base_focus, base_stretch = _SECONDARY_PROJECTILE_DIRECTIONAL.get(type_id, (0.0, 1.0))
    dir_x, dir_y = _normalized_dir_from_vec(entry.vel)
    if abs(dir_x) <= 1e-6 and abs(dir_y) <= 1e-6:
        dir_x, dir_y = _normalized_dir_from_angle(float(entry.angle))
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
        next_lights.append(msgspec.structs.replace(light, age=age))
    return next_lights


def collect_shadow_lights(
    projectiles: list[Projectile],
    secondary_projectiles: list[SecondaryProjectile],
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
        extra_lights = _projectile_lights(
            entry,
            range_scale=range_scale,
            directional_focus=directional_focus,
            directional_stretch=directional_stretch,
        )
        for light in extra_lights:
            if len(lights) >= cap:
                return lights
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
    return int(shader.id) > 0


def _render_texture_valid(rt: rl.RenderTexture | None) -> bool:
    if rt is None:
        return False
    if int(rt.id) <= 0:
        return False
    try:
        validator = rl.is_render_texture_valid
    except AttributeError:
        return True
    try:
        return bool(validator(rt))
    except (RuntimeError, ValueError):
        return False


def _shadow_debug_mode_name(mode: int) -> str:
    index = int(mode)
    if 0 <= index < len(SHADOW_DEBUG_MODE_NAMES):
        return SHADOW_DEBUG_MODE_NAMES[index]
    return f"mode{index}"


class _LightingLocalInputRuntime(LocalInputRuntime):
    view: LightingDebugView

    def capture_frame_inputs(self, frame_ctx: FrameContext) -> list[PlayerInput]:
        return self.view._build_runner_inputs(frame_ctx)


class LightingDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._audio: AudioState | None = None
        self._audio_rng = Crand(0xBEEF)
        self._console: ConsoleState | None = None

        self._runtime = WorldRuntime(
            assets_dir=ctx.assets_dir,
            world_size=float(WORLD_SIZE),
            preserve_bugs=bool(ctx.preserve_bugs),
            audio_rng=self._audio_rng,
        )
        self._runtime.reset(player_count=1)
        self._player = self._runtime.sim_world.players[0] if self._runtime.sim_world.players else None
        self._aim_texture: rl.Texture | None = None

        # Default to Ion Rifle so the first manual shot demonstrates shadows clearly.
        self._profile_index = 1
        self._spawn_preset_index = 0
        self._auto_emit_enabled = False
        self._auto_emit_timer = 0.0
        self._transient_lights: list[TransientLight] = []
        self._static_scene_enabled = False
        self._static_occluders = _build_static_occluders()
        self._static_emitters: list[StaticEmitter] = []
        self._static_selected_emitter = -1
        self._static_drag: _StaticDragState | None = None

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
        self._last_shadow_draw_ms = 0.0

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
        self._dump_mode_target = max(1, int(DUMP_ALL_SETTLE_FRAMES))
        self._dump_total_frames = 0
        self._dump_total_frame = 0
        self._dump_mode_emitter_timer = 0
        self._dump_modes_started = False

        self._auto_tune_enabled, self._auto_tune_sample_frames = self._auto_tune_config_from_env()
        self._auto_tune_started = False
        self._auto_tune_preset_index = 0
        self._auto_tune_preset_frame = 0
        self._auto_tune_accum = _AutoTuneAccumulator()
        self._auto_tune_prev_samples: list[int] | None = None
        self._auto_tune_results: list[_AutoTuneResult] = []

        self.close_requested = False
        self._paused = False
        self._screenshot_requested = False
        self._tick_harness = StandaloneTickHarness(
            game_mode=GameMode.SURVIVAL,
            input_runtime=_LightingLocalInputRuntime(view=self),
        )

    def _load_texture(self, texture_id: TextureId) -> rl.Texture:
        return self._runtime.render_resources.resources.texture(texture_id)

    def _draw_world(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        self._runtime.renderer.draw(
            render_frame=self._runtime.build_render_frame(),
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self._runtime.renderer.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self._runtime.renderer.screen_to_world(pos)

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
    def _auto_tune_config_from_env() -> tuple[bool, int]:
        raw = os.getenv(AUTO_TUNE_ENV)
        if raw is None or raw.strip() == "":
            return False, 0
        value = raw.strip().lower()
        if value in {"0", "false", "off", "no"}:
            return False, 0
        if value in {"1", "true", "on", "yes"}:
            return True, int(AUTO_TUNE_SAMPLE_FRAMES_DEFAULT)
        try:
            frames = int(value)
        except ValueError:
            frames = int(AUTO_TUNE_SAMPLE_FRAMES_DEFAULT)
        return True, max(12, frames)

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
        if key == "rt_scale":
            return float(self._shadow_rt_scale)
        if key == "ambient_darkness":
            return float(self._ambient_darkness)
        if key == "shadow_strength":
            return float(self._shadow_strength)
        if key == "light_size_w":
            return float(self._light_size_w)
        if key == "min_t":
            return float(self._min_t)
        if key == "range_scale":
            return float(self._range_scale)
        if key == "directional_focus":
            return float(self._directional_focus)
        if key == "directional_stretch":
            return float(self._directional_stretch)
        if key == "jitter_amount":
            return float(self._jitter_amount)
        if key == "temporal_response":
            return float(self._temporal_response)
        raise ValueError(f"unknown tune key: {key}")

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
        if param.key == "rt_scale":
            self._shadow_rt_size = (0, 0)
            self._invalidate_shadow_history()

    def _dump_all_total_frames(self) -> int:
        mode_count = max(1, len(self._dump_mode_sequence))
        if self._autodiag_enabled:
            return max(mode_count, int(self._autodiag_total_frames))
        return mode_count * int(DUMP_ALL_SETTLE_FRAMES)

    def _next_dump_mode_target_frames(self) -> int:
        modes_left = max(1, len(self._dump_mode_sequence) - int(self._dump_mode_index))
        frames_left = max(modes_left, int(self._dump_total_frames) - int(self._dump_total_frame))
        return max(1, frames_left // modes_left)

    def _run_autodiag(self) -> None:
        if self._auto_tune_enabled:
            self._run_auto_tune()
            return
        if self._dump_all_modes_enabled:
            self._run_dump_all_modes()
            return
        if not self._autodiag_enabled:
            return

        if not self._autodiag_started:
            self._autodiag_started = True
            if self._static_scene_enabled:
                self._set_static_scene_enabled(False)
            self._shadow_enabled = True
            self._show_debug_overlays = True
            self._show_help = False
            self._paused = False
            self._auto_emit_enabled = False
            self._spawn_preset_ring()
            print(
                f"[lighting-debug] autodiag start frames={self._autodiag_total_frames} seg={AUTODIAG_SEGMENT_FRAMES}",
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
                f"mode={self._shadow_debug_mode}({_shadow_debug_mode_name(self._shadow_debug_mode)})",
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
            if self._static_scene_enabled:
                self._set_static_scene_enabled(False)
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
            self._dump_total_frames = self._dump_all_total_frames()
            self._dump_total_frame = 0
            self._dump_mode_frame = 0
            self._dump_mode_index = 0
            self._dump_mode_target = self._next_dump_mode_target_frames()
            self._dump_mode_emitter_timer = 0
            print(
                "[lighting-debug] dump-all start "
                f"modes={','.join(str(mode) for mode in self._dump_mode_sequence)} "
                f"total_frames={self._dump_total_frames}",
            )

        self._dump_mode_emitter_timer += 1
        if self._dump_mode_emitter_timer >= DUMP_ALL_EMIT_INTERVAL:
            self._dump_mode_emitter_timer = 0
            self._emit_profile()

        mode = int(self._dump_mode_sequence[self._dump_mode_index])
        if self._shadow_debug_mode != mode:
            self._set_shadow_debug_mode(mode)

        self._dump_mode_frame += 1
        self._dump_total_frame += 1
        if self._dump_mode_frame < self._dump_mode_target:
            return

        self._screenshot_requested = True
        print(f"[lighting-debug] dump-all capture mode={mode} ({_shadow_debug_mode_name(mode)})")
        self._dump_mode_frame = 0
        self._dump_mode_index += 1
        if self._dump_mode_index >= len(self._dump_mode_sequence):
            self._screenshot_requested = True
            self.close_requested = True
            print("[lighting-debug] dump-all done")
            return
        self._dump_mode_target = self._next_dump_mode_target_frames()

    def _apply_auto_tune_preset(self, preset: _AutoTunePreset) -> None:
        for key, value in preset.as_tune_values().items():
            self._set_tune_value(key, value, invalidate_history=key != "rt_scale")
            if key == "rt_scale":
                self._shadow_rt_size = (0, 0)
        self._invalidate_shadow_history()

    def _seed_auto_tune_scene(self) -> None:
        self._static_emitters = []
        for x, y, angle, radius, strength, focus, stretch in _AUTO_TUNE_STATIC_EMITTERS:
            self._static_emitters.append(
                StaticEmitter(
                    pos=Vec2(float(x), float(y)),
                    angle=float(angle),
                    radius=_clampf(float(radius), STATIC_LIGHT_RADIUS_MIN, STATIC_LIGHT_RADIUS_MAX),
                    strength=_clampf(float(strength), STATIC_LIGHT_STRENGTH_MIN, STATIC_LIGHT_STRENGTH_MAX),
                    focus=_clampf(float(focus), STATIC_LIGHT_FOCUS_MIN, STATIC_LIGHT_FOCUS_MAX),
                    stretch=_clampf(float(stretch), STATIC_LIGHT_STRETCH_MIN, STATIC_LIGHT_STRETCH_MAX),
                ),
            )
        self._static_selected_emitter = 0 if self._static_emitters else -1
        self._static_drag = None
        self._invalidate_shadow_history()

    def _start_auto_tune(self) -> None:
        self._auto_tune_started = True
        self._auto_tune_results = []
        self._auto_tune_preset_index = 0
        self._auto_tune_preset_frame = 0
        self._auto_tune_accum = _AutoTuneAccumulator()
        self._auto_tune_prev_samples = None

        self._shadow_enabled = True
        self._show_debug_overlays = False
        self._show_help = False
        self._show_tuning_panel = False
        self._paused = False
        self._auto_emit_enabled = False
        self._set_shadow_debug_mode(0)
        if not self._static_scene_enabled:
            self._set_static_scene_enabled(True)
        self._seed_auto_tune_scene()

        preset = _AUTO_TUNE_PRESETS[0]
        self._apply_auto_tune_preset(preset)
        print(
            "[lighting-debug] autotune start "
            f"presets={len(_AUTO_TUNE_PRESETS)} "
            f"warmup={AUTO_TUNE_WARMUP_FRAMES} sample={self._auto_tune_sample_frames}",
        )
        print(f"[lighting-debug] autotune preset=1/{len(_AUTO_TUNE_PRESETS)} name={preset.name}")

    def _run_auto_tune(self) -> None:
        if not self._auto_tune_enabled:
            return
        if not _AUTO_TUNE_PRESETS:
            self._auto_tune_enabled = False
            return
        if not self._auto_tune_started:
            self._start_auto_tune()

    def _shadow_rt_alpha_grid(
        self,
        *,
        rt: rl.RenderTexture,
        max_side: int = AUTO_TUNE_METRIC_GRID,
    ) -> tuple[list[int], int, int] | None:
        if not _render_texture_valid(rt):
            return None
        image = rl.load_image_from_texture(rt.texture)
        try:
            width = max(1, int(image.width))
            height = max(1, int(image.height))
            step_x = max(1, width // max(1, int(max_side)))
            step_y = max(1, height // max(1, int(max_side)))
            xs = list(range(0, width, step_x))
            ys = list(range(0, height, step_y))
            if not xs or not ys:
                return None
            sample_w = len(xs)
            sample_h = len(ys)
            values: list[int] = []
            for y in ys:
                for x in xs:
                    values.append(int(rl.get_image_color(image, x, y).a))
            return values, sample_w, sample_h
        finally:
            rl.unload_image(image)

    def _auto_tune_capture_frame(self, output_rt: rl.RenderTexture | None) -> None:
        if not self._auto_tune_enabled or not self._auto_tune_started:
            return
        if self._auto_tune_preset_index >= len(_AUTO_TUNE_PRESETS):
            return

        self._auto_tune_preset_frame += 1
        if self._auto_tune_preset_frame <= int(AUTO_TUNE_WARMUP_FRAMES):
            return
        if output_rt is None:
            return

        sampled = self._shadow_rt_alpha_grid(rt=output_rt)
        if sampled is None:
            return
        alpha_values, sample_w, sample_h = sampled
        metrics = _shadow_frame_metrics(alpha_values, sample_w, sample_h)
        if metrics is None:
            return

        self._auto_tune_accum.sample_count += 1
        self._auto_tune_accum.shadow_ms_sum += float(self._last_shadow_draw_ms)
        self._auto_tune_accum.mean_sum += float(metrics.mean_alpha)
        self._auto_tune_accum.std_sum += float(metrics.std_alpha)
        self._auto_tune_accum.contrast_sum += float(metrics.contrast)
        self._auto_tune_accum.coverage_sum += float(metrics.coverage)
        self._auto_tune_accum.banding_sum += float(metrics.banding)

        if self._auto_tune_prev_samples is not None and len(self._auto_tune_prev_samples) == len(alpha_values):
            diff_total = 0.0
            for prev, curr in zip(self._auto_tune_prev_samples, alpha_values, strict=False):
                diff_total += abs(float(curr) - float(prev))
            self._auto_tune_accum.flicker_sum += diff_total / float(len(alpha_values))
            self._auto_tune_accum.flicker_count += 1
        self._auto_tune_prev_samples = list(alpha_values)

        if self._auto_tune_accum.sample_count < int(self._auto_tune_sample_frames):
            return
        self._auto_tune_finalize_preset()

    def _auto_tune_finalize_preset(self) -> None:
        if self._auto_tune_preset_index >= len(_AUTO_TUNE_PRESETS):
            return
        preset = _AUTO_TUNE_PRESETS[self._auto_tune_preset_index]
        accum = self._auto_tune_accum
        sample_count = max(1, int(accum.sample_count))
        flicker_count = max(1, int(accum.flicker_count))
        metrics = _ShadowFrameMetrics(
            mean_alpha=float(accum.mean_sum) / float(sample_count),
            std_alpha=float(accum.std_sum) / float(sample_count),
            contrast=float(accum.contrast_sum) / float(sample_count),
            coverage=float(accum.coverage_sum) / float(sample_count),
            banding=float(accum.banding_sum) / float(sample_count),
        )
        avg_shadow_ms = float(accum.shadow_ms_sum) / float(sample_count)
        avg_flicker = float(accum.flicker_sum) / float(flicker_count)
        score = _shadow_quality_score(metrics, shadow_ms=avg_shadow_ms, flicker=avg_flicker)
        result = _AutoTuneResult(
            preset=preset,
            score=float(score),
            shadow_ms=float(avg_shadow_ms),
            mean_alpha=float(metrics.mean_alpha),
            std_alpha=float(metrics.std_alpha),
            contrast=float(metrics.contrast),
            coverage=float(metrics.coverage),
            banding=float(metrics.banding),
            flicker=float(avg_flicker),
        )
        self._auto_tune_results.append(result)

        print(
            "[lighting-debug] autotune result "
            f"name={preset.name} score={result.score:.3f} "
            f"shadow_ms={result.shadow_ms:.3f} mean={result.mean_alpha:.1f} "
            f"std={result.std_alpha:.1f} contrast={result.contrast:.3f} "
            f"coverage={result.coverage:.3f} banding={result.banding:.3f} flicker={result.flicker:.2f}",
        )
        self._screenshot_requested = True

        self._auto_tune_preset_index += 1
        if self._auto_tune_preset_index >= len(_AUTO_TUNE_PRESETS):
            self._auto_tune_enabled = False
            self._auto_tune_started = False
            if not self._auto_tune_results:
                self.close_requested = True
                return
            ranked = sorted(self._auto_tune_results, key=_auto_tune_selection_score, reverse=True)
            for rank, item in enumerate(ranked, start=1):
                print(
                    "[lighting-debug] autotune rank "
                    f"{rank}/{len(ranked)} name={item.preset.name} score={item.score:.3f} "
                    f"select={_auto_tune_selection_score(item):.3f} "
                    f"shadow_ms={item.shadow_ms:.3f} banding={item.banding:.3f}",
                )
            best = ranked[0]
            self._apply_auto_tune_preset(best.preset)
            print(
                "[lighting-debug] autotune best "
                f"name={best.preset.name} score={best.score:.3f} "
                "values="
                f"ambient={best.preset.ambient_darkness:.3f} "
                f"reveal={best.preset.shadow_strength:.3f} "
                f"light_w={best.preset.light_size_w:.3f} "
                f"min_t={best.preset.min_t:.3f} "
                f"range={best.preset.range_scale:.3f} "
                f"dir_focus={best.preset.directional_focus:.3f} "
                f"dir_stretch={best.preset.directional_stretch:.3f} "
                f"jitter={best.preset.jitter_amount:.3f} "
                f"temporal={best.preset.temporal_response:.3f} "
                f"rt_scale={best.preset.rt_scale:.3f}",
            )
            self._screenshot_requested = True
            self.close_requested = True
            return

        self._auto_tune_preset_frame = 0
        self._auto_tune_accum = _AutoTuneAccumulator()
        self._auto_tune_prev_samples = None
        next_preset = _AUTO_TUNE_PRESETS[self._auto_tune_preset_index]
        self._apply_auto_tune_preset(next_preset)
        print(
            f"[lighting-debug] autotune preset={self._auto_tune_preset_index + 1}/{len(_AUTO_TUNE_PRESETS)} "
            f"name={next_preset.name}",
        )

    def _shadow_rt_alpha_stats(self) -> tuple[int, float, int] | None:
        rt = self._shadow_rt
        if rt is None or not _render_texture_valid(rt):
            return None
        sampled = self._shadow_rt_alpha_grid(rt=rt, max_side=64)
        if sampled is None:
            return None
        alpha_values, _sample_w, _sample_h = sampled
        if not alpha_values:
            return None
        min_alpha = min(alpha_values)
        max_alpha = max(alpha_values)
        avg = sum(float(alpha) for alpha in alpha_values) / float(len(alpha_values))
        return int(min_alpha), float(avg), int(max_alpha)

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
            f"alpha(min/avg/max)=({min_alpha},{avg_alpha:.1f},{max_alpha})",
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
        self._runtime.sim_world.creatures.reset()
        self._runtime.sim_world.state.projectiles.reset()
        self._runtime.sim_world.state.secondary_projectiles.reset()
        self._runtime.sim_world.state.particles.reset()
        self._runtime.sim_world.state.sprite_effects.reset()
        self._runtime.sim_world.state.effects.reset()
        self._runtime.sim_world.state.bonus_pool.reset()
        self._runtime.render_resources.clear_pending_terrain_fx()
        self._transient_lights.clear()
        self._invalidate_shadow_history()

    @staticmethod
    def _clamp_world_pos(pos: Vec2, *, margin: float = 12.0) -> Vec2:
        return pos.clamp_rect(float(margin), float(margin), WORLD_SIZE - float(margin), WORLD_SIZE - float(margin))

    @staticmethod
    def _mouse_screen() -> Vec2:
        return Vec2.from_xy(rl.get_mouse_position())

    def _mouse_world(self) -> Vec2:
        return self.screen_to_world(self._mouse_screen())

    def _set_static_scene_enabled(self, enabled: bool) -> None:
        next_enabled = bool(enabled)
        if self._static_scene_enabled == next_enabled:
            return
        self._static_scene_enabled = next_enabled
        self._static_drag = None
        self._static_selected_emitter = -1
        self._auto_emit_enabled = False
        self._auto_emit_timer = 0.0
        self._invalidate_shadow_history()

        if self._static_scene_enabled:
            self._clear_scene_contents()
            self._seed_static_scene()
            self._runtime.update_camera()
            return

        self._reset_scene()

    def _seed_static_scene(self) -> None:
        self._static_emitters = []
        profile = self._selected_profile()
        radius, strength, focus, stretch = _profile_light_defaults(profile)
        self._static_emitters.append(
            StaticEmitter(
                pos=Vec2(510.0, 400.0),
                angle=-2.55,
                radius=_clampf(radius, STATIC_LIGHT_RADIUS_MIN, STATIC_LIGHT_RADIUS_MAX),
                strength=_clampf(strength, STATIC_LIGHT_STRENGTH_MIN, STATIC_LIGHT_STRENGTH_MAX),
                focus=_clampf(focus, STATIC_LIGHT_FOCUS_MIN, STATIC_LIGHT_FOCUS_MAX),
                stretch=_clampf(stretch, STATIC_LIGHT_STRETCH_MIN, STATIC_LIGHT_STRETCH_MAX),
            ),
        )
        self._static_selected_emitter = 0

    def _make_static_emitter(self, pos: Vec2) -> StaticEmitter:
        profile = self._selected_profile()
        radius, strength, focus, stretch = _profile_light_defaults(profile)
        return StaticEmitter(
            pos=self._clamp_world_pos(pos),
            angle=0.0,
            radius=_clampf(radius, STATIC_LIGHT_RADIUS_MIN, STATIC_LIGHT_RADIUS_MAX),
            strength=_clampf(strength, STATIC_LIGHT_STRENGTH_MIN, STATIC_LIGHT_STRENGTH_MAX),
            focus=_clampf(focus, STATIC_LIGHT_FOCUS_MIN, STATIC_LIGHT_FOCUS_MAX),
            stretch=_clampf(stretch, STATIC_LIGHT_STRETCH_MIN, STATIC_LIGHT_STRETCH_MAX),
        )

    def _static_handle_positions(self, emitter: StaticEmitter) -> dict[str, Vec2]:
        dir_vec = Vec2.from_heading(float(emitter.angle))
        dir_len = max(24.0, min(float(emitter.radius) * 0.55, 180.0))
        return {
            "move": emitter.pos,
            "radius": emitter.pos + Vec2(float(emitter.radius), 0.0),
            "direction": emitter.pos + dir_vec * dir_len,
            "strength": emitter.pos + Vec2(0.0, -34.0),
            "stretch": emitter.pos + Vec2(0.0, 34.0),
        }

    def _nearest_static_emitter(self, mouse_screen: Vec2, *, max_dist_px: float) -> int:
        if not self._static_emitters:
            return -1
        best_index = -1
        best_d2 = float(max_dist_px) * float(max_dist_px)
        for idx, emitter in enumerate(self._static_emitters):
            screen = self.world_to_screen(emitter.pos)
            d2 = _screen_distance_sq(screen, mouse_screen)
            if d2 <= best_d2:
                best_d2 = d2
                best_index = idx
        return best_index

    def _set_static_emitter(self, index: int, emitter: StaticEmitter) -> None:
        if 0 <= index < len(self._static_emitters):
            self._static_emitters[index] = emitter
            self._invalidate_shadow_history()

    def _place_static_emitter_at_mouse(self) -> None:
        pos = self._mouse_world()
        self._static_emitters.append(self._make_static_emitter(pos))
        if len(self._static_emitters) > MAX_LIGHTS:
            self._static_emitters = self._static_emitters[-MAX_LIGHTS:]
        self._static_selected_emitter = len(self._static_emitters) - 1
        self._invalidate_shadow_history()

    def _remove_static_emitter_at_mouse(self) -> None:
        mouse_screen = self._mouse_screen()
        idx = self._nearest_static_emitter(mouse_screen, max_dist_px=18.0)
        if idx < 0:
            return
        del self._static_emitters[idx]
        if not self._static_emitters:
            self._static_selected_emitter = -1
        else:
            self._static_selected_emitter = max(0, min(self._static_selected_emitter, len(self._static_emitters) - 1))
        self._invalidate_shadow_history()

    def _begin_static_drag(self, *, kind: str, index: int) -> None:
        if not (0 <= index < len(self._static_emitters)):
            self._static_drag = None
            return
        emitter = self._static_emitters[index]
        mouse_world = self._mouse_world()
        mouse_screen = self._mouse_screen()
        value_start = 0.0
        if kind == "strength":
            value_start = float(emitter.strength)
        elif kind == "stretch":
            value_start = float(emitter.stretch)
        self._static_drag = _StaticDragState(
            kind=str(kind),
            emitter_index=int(index),
            mouse_start_world=mouse_world,
            mouse_start_screen=mouse_screen,
            pos_offset=emitter.pos - mouse_world,
            value_start=value_start,
        )

    def _update_static_drag(self) -> None:
        drag = self._static_drag
        if drag is None:
            return
        if not rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._static_drag = None
            return
        index = int(drag.emitter_index)
        if not (0 <= index < len(self._static_emitters)):
            self._static_drag = None
            return
        emitter = self._static_emitters[index]
        mouse_world = self._mouse_world()
        mouse_screen = self._mouse_screen()

        kind = drag.kind
        if kind == "move":
            next_pos = self._clamp_world_pos(mouse_world + drag.pos_offset)
            self._set_static_emitter(
                index,
                StaticEmitter(
                    next_pos, emitter.angle, emitter.radius, emitter.strength, emitter.focus, emitter.stretch,
                ),
            )
            return
        if kind == "radius":
            radius = _clampf((mouse_world - emitter.pos).length(), STATIC_LIGHT_RADIUS_MIN, STATIC_LIGHT_RADIUS_MAX)
            self._set_static_emitter(
                index,
                StaticEmitter(emitter.pos, emitter.angle, radius, emitter.strength, emitter.focus, emitter.stretch),
            )
            return
        if kind == "direction":
            delta = mouse_world - emitter.pos
            length = delta.length()
            if length > 1e-4:
                angle = float(delta.to_heading())
                focus = _clampf(
                    length / max(1.0, float(emitter.radius) * 0.55), STATIC_LIGHT_FOCUS_MIN, STATIC_LIGHT_FOCUS_MAX,
                )
                self._set_static_emitter(
                    index,
                    StaticEmitter(emitter.pos, angle, emitter.radius, emitter.strength, focus, emitter.stretch),
                )
            return
        if kind == "strength":
            delta_x = float(mouse_screen.x - drag.mouse_start_screen.x)
            strength = _clampf(
                float(drag.value_start) + delta_x * 0.010,
                STATIC_LIGHT_STRENGTH_MIN,
                STATIC_LIGHT_STRENGTH_MAX,
            )
            self._set_static_emitter(
                index,
                StaticEmitter(emitter.pos, emitter.angle, emitter.radius, strength, emitter.focus, emitter.stretch),
            )
            return
        if kind == "stretch":
            delta_x = float(mouse_screen.x - drag.mouse_start_screen.x)
            stretch = _clampf(
                float(drag.value_start) + delta_x * 0.010,
                STATIC_LIGHT_STRETCH_MIN,
                STATIC_LIGHT_STRETCH_MAX,
            )
            self._set_static_emitter(
                index,
                StaticEmitter(emitter.pos, emitter.angle, emitter.radius, emitter.strength, emitter.focus, stretch),
            )
            return

        self._static_drag = None

    def _handle_static_mouse_input(self) -> None:
        self._update_static_drag()
        if not rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            return

        mouse_screen = self._mouse_screen()
        hit_radius_sq = STATIC_HANDLE_HIT_RADIUS_PX * STATIC_HANDLE_HIT_RADIUS_PX

        selected = self._static_selected_emitter
        if 0 <= selected < len(self._static_emitters):
            emitter = self._static_emitters[selected]
            handles = self._static_handle_positions(emitter)
            for kind in ("move", "radius", "direction", "strength", "stretch"):
                screen = self.world_to_screen(handles[kind])
                if _screen_distance_sq(screen, mouse_screen) <= hit_radius_sq:
                    self._begin_static_drag(kind=kind, index=selected)
                    return

        nearest = self._nearest_static_emitter(mouse_screen, max_dist_px=STATIC_HANDLE_HIT_RADIUS_PX)
        if nearest >= 0:
            self._static_selected_emitter = nearest
            self._begin_static_drag(kind="move", index=nearest)
            return

        self._place_static_emitter_at_mouse()
        self._begin_static_drag(kind="move", index=self._static_selected_emitter)

    def _collect_static_shadow_state(self) -> None:
        occluders = self._static_occluders[:MAX_OCCLUDERS]
        self._last_occluders = [
            CircleOccluder(pos=Vec2(float(occ.pos.x), float(occ.pos.y)), radius=float(occ.radius)) for occ in occluders
        ]

        lights: list[ShadowLight] = []
        for emitter in self._static_emitters:
            if len(lights) >= MAX_LIGHTS:
                break
            dir_vec = Vec2.from_heading(float(emitter.angle))
            radius = min(STATIC_LIGHT_RADIUS_MAX, float(emitter.radius) * float(self._range_scale))
            focus = _clampf(float(emitter.focus) * float(self._directional_focus), 0.0, 2.0)
            stretch = _clampf(float(emitter.stretch) * float(self._directional_stretch), 1.0, 6.0)
            lights.append(
                ShadowLight(
                    pos=Vec2(float(emitter.pos.x), float(emitter.pos.y)),
                    radius=float(radius),
                    strength=_clampf(float(emitter.strength), STATIC_LIGHT_STRENGTH_MIN, STATIC_LIGHT_STRENGTH_MAX),
                    dir_x=float(dir_vec.x),
                    dir_y=float(dir_vec.y),
                    focus=float(focus),
                    stretch=float(stretch),
                ),
            )
        self._last_lights = lights

    def _reset_scene(self) -> None:
        self._runtime.reset(seed=0xBEEF, player_count=1, spawn_pos=WORLD_CENTER)
        self._reset_tick_runner()
        self._player = self._runtime.sim_world.players[0] if self._runtime.sim_world.players else None
        self._apply_debug_player_cheats()
        self._clear_scene_contents()
        self._static_emitters = []
        self._static_selected_emitter = -1
        self._static_drag = None
        # Seed a default occluder ring so shadows are visible immediately on first emission.
        self._spawn_preset_ring()
        self._auto_emit_timer = 0.0
        self._shadow_frame_index = 0
        self._runtime.update_camera()

    def _build_input(self) -> PlayerInput:
        move = Vec2(
            float(rl.is_key_down(rl.KeyboardKey.KEY_D)) - float(rl.is_key_down(rl.KeyboardKey.KEY_A)),
            float(rl.is_key_down(rl.KeyboardKey.KEY_S)) - float(rl.is_key_down(rl.KeyboardKey.KEY_W)),
        )
        mouse = rl.get_mouse_position()
        aim = self.screen_to_world(Vec2.from_xy(mouse))
        return PlayerInput(
            move=move,
            aim=aim,
            fire_down=False,
            fire_pressed=False,
            reload_pressed=False,
        )

    def _build_runner_inputs(self, frame_ctx: FrameContext) -> list[PlayerInput]:
        _ = frame_ctx
        return [self._build_input()]

    def _reset_tick_runner(self) -> None:
        self._tick_harness.reset()

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
            8.0,
            8.0,
            WORLD_SIZE - 8.0,
            WORLD_SIZE - 8.0,
        )

        if profile.secondary_type_id == SecondaryProjectileTypeId.DETONATION:
            impact = (player.pos + aim_dir * float(profile.explosion_distance)).clamp_rect(
                16.0,
                16.0,
                WORLD_SIZE - 16.0,
                WORLD_SIZE - 16.0,
            )
            self._runtime.sim_world.state.secondary_projectiles.spawn_from_spec(
                SecondarySpawnSpec(
                    pos=impact,
                    angle=float(heading),
                    type_id=SecondaryProjectileTypeId.DETONATION,
                    owner=OwnerRef.from_local_player(0),
                    time_to_live=float(profile.secondary_ttl),
                ),
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
                self._runtime.sim_world.state.projectiles.spawn(
                    pos=muzzle_pos,
                    angle=angle,
                    type_id=profile.primary_type_id,
                    owner=OwnerRef.from_local_player(0),
                )
            if profile.secondary_type_id is not None:
                self._runtime.sim_world.state.secondary_projectiles.spawn_from_spec(
                    SecondarySpawnSpec(
                        pos=muzzle_pos,
                        angle=angle,
                        type_id=profile.secondary_type_id,
                        owner=OwnerRef.from_local_player(0),
                        time_to_live=float(profile.secondary_ttl),
                        creatures=self._runtime.sim_world.creatures.entries,
                        target_hint=player.aim,
                    ),
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
                48.0,
                48.0,
                WORLD_SIZE - 48.0,
                WORLD_SIZE - 48.0,
            )
            heading = angle + math.pi
            self._runtime.sim_world.creatures.spawn_template(
                preset.spawn_id,
                pos,
                heading,
                self._runtime.sim_world.state.rng,
            )

    def _clear_spawned_enemies(self) -> None:
        self._runtime.sim_world.creatures.reset()

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
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F4) and not self._static_scene_enabled:
            self._auto_emit_enabled = not self._auto_emit_enabled
            self._auto_emit_timer = 0.0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F5):
            self._set_static_scene_enabled(not self._static_scene_enabled)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F6):
            self._set_shadow_debug_mode(self._shadow_debug_mode + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F7):
            self._reset_tuning_defaults()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F8):
            self._show_tuning_panel = not self._show_tuning_panel
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F9):
            if self._auto_tune_enabled:
                self._auto_tune_enabled = False
                self._auto_tune_started = False
            else:
                self._auto_tune_enabled = True
                self._auto_tune_started = False
                self._auto_tune_sample_frames = int(AUTO_TUNE_SAMPLE_FRAMES_DEFAULT)

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
            if self._static_scene_enabled:
                self._seed_static_scene()
                self._clear_scene_contents()
            else:
                self._reset_scene()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True
        if self._static_scene_enabled:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_DELETE):
                self._seed_static_scene()
                self._clear_scene_contents()
            if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT):
                self._remove_static_emitter_at_mouse()
            self._handle_static_mouse_input()
            return

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
            cooldown = WEAPON_BY_ID[WeaponId(weapon_id)].shot_cooldown
            return max(0.001, float(cooldown))
        return max(0.001, float(profile.auto_interval))

    def _collect_shadow_state(self) -> None:
        if self._static_scene_enabled:
            self._collect_static_shadow_state()
            return
        self._last_occluders = collect_shadow_occluders(
            self._player,
            self._runtime.sim_world.creatures.entries,
            max_occluders=MAX_OCCLUDERS,
        )
        self._last_lights = collect_shadow_lights(
            self._runtime.sim_world.state.projectiles.entries,
            self._runtime.sim_world.state.secondary_projectiles.entries,
            self._transient_lights,
            max_lights=MAX_LIGHTS,
            range_scale=self._range_scale,
            directional_focus=self._directional_focus,
            directional_stretch=self._directional_stretch,
        )

    def open(self) -> None:
        self._missing_assets.clear()

        bootstrap = init_view_audio(self._assets_root)
        self._runtime.config = bootstrap.config
        self._console = bootstrap.console
        self._audio = bootstrap.audio
        self._audio_rng = bootstrap.audio_rng
        self._runtime.audio = self._audio
        self._runtime.audio_rng = self._audio_rng
        self._runtime.sync_audio_bridge_state()

        try:
            # Load after audio/bootstrap so missing PAQs can be downloaded first.
            self._small = load_small_font(self._assets_root)
        except FileNotFoundError:
            self._small = None
            self._missing_assets.append("load/smallFnt.dat + load/smallWhite.tga")

        self._runtime.open_runtime()
        self._aim_texture = self._load_texture(TextureId.UI_AIM)
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
        self._reset_tick_runner()
        self._release_shadow_resources()

        if self._small is not None:
            self._small = None
        if self._audio is not None:
            shutdown_audio(self._audio)
            self._audio = None
            self._console = None
        self._runtime.audio = None
        self._runtime.audio_rng = self._audio_rng
        self._runtime.sync_audio_bridge_state()
        self._runtime.close_runtime()
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
                f"light1={uniforms.lights[1] if len(uniforms.lights) > 1 else -1}",
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
            if name == "resolution":
                value = uniforms.resolution
            elif name == "rt_resolution":
                value = uniforms.rt_resolution
            elif name == "camera":
                value = uniforms.camera
            elif name == "view_scale":
                value = uniforms.view_scale
            elif name == "occluder_count":
                value = uniforms.occluder_count
            elif name == "light_count":
                value = uniforms.light_count
            elif name == "light_size_w":
                value = uniforms.light_size_w
            elif name == "shadow_strength":
                value = uniforms.shadow_strength
            elif name == "ambient_darkness":
                value = uniforms.ambient_darkness
            elif name == "min_t":
                value = uniforms.min_t
            elif name == "jitter_phase":
                value = uniforms.jitter_phase
            elif name == "jitter_amount":
                value = uniforms.jitter_amount
            else:
                if name != "debug_mode":
                    raise ValueError(f"unknown shadow uniform: {name}")
                value = uniforms.debug_mode
            if int(value) < 0:
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

        camera, view_scale = self._runtime.renderer._world_params()
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
        start_time = time.perf_counter()
        output_rt: rl.RenderTexture | None = None
        if not self._shadow_enabled:
            self._shadow_output_rt_for_preview = None
            self._last_shadow_draw_ms = (time.perf_counter() - start_time) * 1000.0
            return
        if not self._ensure_shadow_shader():
            self._last_shadow_draw_ms = (time.perf_counter() - start_time) * 1000.0
            return
        if not self._ensure_shadow_rt():
            self._last_shadow_draw_ms = (time.perf_counter() - start_time) * 1000.0
            return
        if self._shadow_rt is None or self._shadow_shader is None:
            self._last_shadow_draw_ms = (time.perf_counter() - start_time) * 1000.0
            return

        try:
            self._set_shadow_uniforms(occluders=self._last_occluders, lights=self._last_lights)
        except (RuntimeError, ValueError, TypeError) as exc:
            self._shadow_warning = f"shadow uniform update failed: {exc}"
            self._last_shadow_draw_ms = (time.perf_counter() - start_time) * 1000.0
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
            self._last_shadow_draw_ms = (time.perf_counter() - start_time) * 1000.0
            return
        src = rl.Rectangle(0.0, 0.0, float(rt_w), -float(rt_h))
        dst = rl.Rectangle(0.0, 0.0, float(rl.get_screen_width()), float(rl.get_screen_height()))
        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
        rl.draw_texture_pro(output_rt.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        rl.end_blend_mode()

        self._last_shadow_draw_ms = (time.perf_counter() - start_time) * 1000.0
        self._auto_tune_capture_frame(output_rt)

    def update(self, dt: float) -> None:
        self._player = self._runtime.sim_world.players[0] if self._runtime.sim_world.players else None
        self._handle_debug_input()
        self._run_autodiag()

        sim_dt = float(dt)
        if self._paused:
            sim_dt = 0.0

        if self._static_scene_enabled:
            self._runtime.update_camera()
        elif self._player is not None:
            self._apply_debug_player_cheats()
            self._update_auto_emit(sim_dt)
            self._tick_harness.advance_frame(self._runtime, float(sim_dt))
        elif self._runtime.sim_world.players:
            self._player = self._runtime.sim_world.players[0]

        if not self._static_scene_enabled:
            self._transient_lights = tick_transient_lights(self._transient_lights, sim_dt)
        self._collect_shadow_state()

        if self._audio is not None:
            update_audio(self._audio, sim_dt)

    def _world_scale(self) -> float:
        _camera, view_scale = self._runtime.renderer._world_params()
        return view_scale.avg_component()

    def _draw_shadow_debug_geometry(self) -> None:
        scale = self._world_scale()
        for occluder in self._last_occluders:
            screen = self.world_to_screen(occluder.pos)
            radius = max(1.0, float(occluder.radius) * scale)
            rl.draw_circle_lines(int(screen.x), int(screen.y), int(radius), OCCLUDER_COLOR)

        for light in self._last_lights:
            screen = self.world_to_screen(light.pos)
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

    def _draw_static_emitter_controls(self) -> None:
        if not self._static_scene_enabled:
            return
        scale = self._world_scale()
        for idx, emitter in enumerate(self._static_emitters):
            selected = idx == self._static_selected_emitter
            handles = self._static_handle_positions(emitter)
            center_screen = self.world_to_screen(handles["move"])
            radius_screen = self.world_to_screen(handles["radius"])
            direction_screen = self.world_to_screen(handles["direction"])
            strength_screen = self.world_to_screen(handles["strength"])
            stretch_screen = self.world_to_screen(handles["stretch"])

            if selected:
                radius = max(1.0, float(emitter.radius) * scale)
                rl.draw_circle_lines(int(center_screen.x), int(center_screen.y), int(radius), LIGHT_SELECTED_COLOR)

            rl.draw_line_ex(
                rl.Vector2(float(center_screen.x), float(center_screen.y)),
                rl.Vector2(float(radius_screen.x), float(radius_screen.y)),
                1.5,
                LIGHT_HANDLE_RADIUS,
            )
            rl.draw_line_ex(
                rl.Vector2(float(center_screen.x), float(center_screen.y)),
                rl.Vector2(float(direction_screen.x), float(direction_screen.y)),
                2.0,
                LIGHT_HANDLE_DIR,
            )
            rl.draw_line_ex(
                rl.Vector2(float(center_screen.x), float(center_screen.y)),
                rl.Vector2(float(strength_screen.x), float(strength_screen.y)),
                1.5,
                LIGHT_HANDLE_STRENGTH,
            )
            rl.draw_line_ex(
                rl.Vector2(float(center_screen.x), float(center_screen.y)),
                rl.Vector2(float(stretch_screen.x), float(stretch_screen.y)),
                1.5,
                LIGHT_HANDLE_STRETCH,
            )

            handle_radius = STATIC_HANDLE_DRAW_RADIUS_PX + (2.0 if selected else 0.0)
            rl.draw_circle_v(
                rl.Vector2(float(center_screen.x), float(center_screen.y)), handle_radius, LIGHT_HANDLE_MOVE,
            )
            rl.draw_circle_v(
                rl.Vector2(float(radius_screen.x), float(radius_screen.y)), handle_radius, LIGHT_HANDLE_RADIUS,
            )
            rl.draw_circle_v(
                rl.Vector2(float(direction_screen.x), float(direction_screen.y)), handle_radius, LIGHT_HANDLE_DIR,
            )
            rl.draw_circle_v(
                rl.Vector2(float(strength_screen.x), float(strength_screen.y)), handle_radius, LIGHT_HANDLE_STRENGTH,
            )
            rl.draw_circle_v(
                rl.Vector2(float(stretch_screen.x), float(stretch_screen.y)), handle_radius, LIGHT_HANDLE_STRETCH,
            )

            if selected and self._small is not None:
                draw_ui_text(
                    self._small,
                    (
                        f"light {idx + 1}/{len(self._static_emitters)} "
                        f"r{emitter.radius:.0f} s{emitter.strength:.2f} "
                        f"f{emitter.focus:.2f} st{emitter.stretch:.2f}"
                    ),
                    Vec2(center_screen.x + 12.0, center_screen.y - 28.0),
                    color=LIGHT_SELECTED_COLOR,
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
        creatures_alive = sum(
            1 for creature in self._runtime.sim_world.creatures.entries if creature.active and creature.hp > 0.0
        )
        primary_count = sum(1 for entry in self._runtime.sim_world.state.projectiles.entries if entry.active)
        secondary_count = sum(
            1 for entry in self._runtime.sim_world.state.secondary_projectiles.entries if entry.active
        )

        draw_ui_text(self._small, "Lighting debug: 2D SDF soft shadows", Vec2(x, y), color=UI_TEXT)
        y += line
        draw_ui_text(
            self._small,
            f"scene {'static look-dev' if self._static_scene_enabled else 'dynamic sandbox'}",
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        draw_ui_text(
            self._small,
            (
                f"profile {self._profile_index + 1}/{len(EMISSIVE_PROFILES)}: {profile.name}  new-light defaults"
                if self._static_scene_enabled
                else f"profile {self._profile_index + 1}/{len(EMISSIVE_PROFILES)}: {profile.name}  "
                f"auto {'on' if self._auto_emit_enabled else 'off'} ({self._profile_auto_interval(profile):.3f}s)"
            ),
            Vec2(x, y),
            color=UI_TEXT,
        )
        y += line
        if not self._static_scene_enabled:
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
        if self._static_scene_enabled:
            draw_ui_text(
                self._small,
                f"static emitters {len(self._static_emitters)}/{MAX_LIGHTS}",
                Vec2(x, y),
                color=UI_TEXT,
            )
            y += line
        else:
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
            (
                "note: static mode uses fixed circle occluders and manual emitters"
                if self._static_scene_enabled
                else "note: only player + creature hitboxes cast shadows in this pass"
            ),
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
        y += line
        if self._auto_tune_enabled:
            preset_count = len(_AUTO_TUNE_PRESETS)
            if self._auto_tune_started and 0 <= self._auto_tune_preset_index < preset_count:
                preset = _AUTO_TUNE_PRESETS[self._auto_tune_preset_index]
                draw_ui_text(
                    self._small,
                    (
                        f"autotune {self._auto_tune_preset_index + 1}/{preset_count} {preset.name}  "
                        f"frame {self._auto_tune_preset_frame}/{AUTO_TUNE_WARMUP_FRAMES + self._auto_tune_sample_frames}"
                    ),
                    Vec2(x, y),
                    color=UI_HINT,
                )
            else:
                draw_ui_text(self._small, "autotune pending", Vec2(x, y), color=UI_HINT)

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
            (
                "LMB place/select/drag light  RMB remove light  Del reset lights  [/] profile defaults"
                if self._static_scene_enabled
                else "WASD move  LMB emit  [/] projectile profile  F4 auto emit"
            ),
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(
            self._small,
            (
                "drag handles: blue move  amber radius  white direction/focus  pink strength  green stretch"
                if self._static_scene_enabled
                else ",/. spawn preset  N spawn ring  M clear enemies  Backspace reset scene"
            ),
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(
            self._small,
            "F2 shadows  F3 overlays  F5 static scene  F6 shader dbg  F7 tune defaults  F8 tuning panel  F9 autotune",
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
        self._draw_world(draw_aim_indicators=True)
        self._draw_shadow_overlay()

        if self._show_debug_overlays:
            self._draw_shadow_debug_geometry()
            self._draw_static_emitter_controls()
            self._draw_shadow_preview()
        self._draw_overlay_ui()

        if self._missing_assets:
            draw_ui_text(
                self._small,
                "Missing assets: " + ", ".join(self._missing_assets),
                Vec2(16.0, 16.0),
                color=UI_ERROR,
            )

        resources = self._runtime.render_resources.resources
        mouse = rl.get_mouse_position()
        draw_aim_cursor(resources.texture(TextureId.PARTICLES), self._aim_texture, pos=Vec2.from_xy(mouse))


@register_view("lighting-debug", "Lighting debug")
def build_lighting_debug_view(ctx: ViewContext) -> ViewInstance:
    view = LightingDebugView(ctx)
    return ViewInstance(
        view,
        RunViewHooks(
            should_close=lambda: view.close_requested,
            consume_screenshot_request=view.consume_screenshot_request,
        ),
    )
