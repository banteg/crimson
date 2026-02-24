#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bootstrap::{apply_replay_bootstrap, ReplayBootstrapError};
use crate::rand::CrtRand;
use crate::replay::{load_replay, PackedPlayerInput, Replay, ReplayCodecError, ReplayEvent};
use crate::tables::{
    DEATH_CLOCK_BLOCKED, PERK_ALWAYS_AVAILABLE, PERK_BASE_AVAILABLE_MAX_ID, PERK_RARITY_GATE,
    PERK_SPECS, QUEST_UNLOCK_PERK_IDS, QUEST_UNLOCK_WEAPON_IDS, WEAPON_SPECS,
};

pub const REPLAY_VERIFY_SCHEMA_VERSION: i64 = 1;
pub const REPLAY_VERIFY_SCORE_MISMATCH_EXIT_CODE: i32 = 3;

const FIRE_DOWN_FLAG: i64 = 1 << 0;
const FIRE_PRESSED_FLAG: i64 = 1 << 1;
const RELOAD_PRESSED_FLAG: i64 = 1 << 2;
const MOVE_KEYS_PRESENT_FLAG: i64 = 1 << 3;
const MOVE_FORWARD_FLAG: i64 = 1 << 4;
const MOVE_BACKWARD_FLAG: i64 = 1 << 5;
const TURN_LEFT_FLAG: i64 = 1 << 6;
const TURN_RIGHT_FLAG: i64 = 1 << 7;
const MOVE_MODE_PRESENT_FLAG: i64 = 1 << 8;
const MOVE_MODE_SHIFT: i64 = 9;
const MOVE_MODE_MASK: i64 = 0x7;
const AIM_SCHEME_PRESENT_FLAG: i64 = 1 << 12;
const AIM_SCHEME_SHIFT: i64 = 13;
const AIM_SCHEME_MASK: i64 = 0x7;

const MOVEMENT_CONTROL_TYPE_UNKNOWN: i64 = 0;
const MOVEMENT_CONTROL_TYPE_RELATIVE: i64 = 1;
const MOVEMENT_CONTROL_TYPE_STATIC: i64 = 2;
const MOVEMENT_CONTROL_TYPE_DUAL_ACTION_PAD: i64 = 3;
const MOVEMENT_CONTROL_TYPE_MOUSE_POINT_CLICK: i64 = 4;
const MOVEMENT_CONTROL_TYPE_COMPUTER: i64 = 5;

const AIM_SCHEME_UNKNOWN: i64 = -1;
const AIM_SCHEME_MOUSE: i64 = 0;
const AIM_SCHEME_KEYBOARD: i64 = 1;
const AIM_SCHEME_JOYSTICK: i64 = 2;
const AIM_SCHEME_COMPUTER: i64 = 5;

const GAME_MODE_SURVIVAL: i64 = 1;
const GAME_MODE_RUSH: i64 = 2;
const GAME_MODE_QUESTS: i64 = 3;

const PERK_COUNT_SIZE: usize = 0x80;
const WEAPON_COUNT_SIZE: usize = 0x80;
const WEAPON_USAGE_COUNT: usize = 53;
const WEAPON_DROP_ID_COUNT: u32 = 0x21;

const PERK_FLAGS_QUEST_ALLOWED: u8 = 0x1;
const PERK_FLAGS_TWO_PLAYER_ALLOWED: u8 = 0x2;
const PERK_FLAGS_STACKABLE: u8 = 0x4;

const PERK_ANTIPERK: usize = 0;
const PERK_BLOODY_MESS_QUICK_LEARNER: usize = 1;
const PERK_SHARPSHOOTER: usize = 2;
const PERK_FASTLOADER: usize = 3;
const PERK_LONG_DISTANCE_RUNNER: usize = 5;
const PERK_FASTSHOT: usize = 14;
const PERK_FATAL_LOTTERY: usize = 15;
const PERK_RANDOM_WEAPON: usize = 16;
const PERK_ANXIOUS_LOADER: usize = 18;
const PERK_PERK_EXPERT: usize = 21;
const PERK_REGRESSION_BULLETS: usize = 23;
const PERK_INFERNAL_CONTRACT: usize = 24;
const PERK_URANIUM_FILLED_BULLETS: usize = 28;
const PERK_DOCTOR: usize = 29;
const PERK_BARREL_GREASER: usize = 34;
const PERK_PYROMANIAC: usize = 39;
const PERK_PERK_MASTER: usize = 43;
const PERK_BREATHING_ROOM: usize = 46;
const PERK_DEATH_CLOCK: usize = 47;
const PERK_MY_FAVOURITE_WEAPON: usize = 48;
const PERK_BANDAGE: usize = 49;
const PERK_ANGRY_RELOADER: usize = 50;
const PERK_LIFELINE_50_50: usize = 57;
const PERK_THICK_SKINNED: usize = 33;
const PERK_AMMUNITION_WITHIN: usize = 35;
const PERK_GRIM_DEAL: usize = 8;
const PERK_AMMO_MANIAC: usize = 12;
const PERK_INSTANT_WINNER: usize = 7;
const PERK_ALTERNATE_WEAPON: usize = 9;
const PERK_DODGER: usize = 26;
const PERK_POISON_BULLETS: usize = 25;
const PERK_UNSTOPPABLE: usize = 22;
const PERK_FINAL_REVENGE: usize = 19;
const PERK_TOUGH_RELOADER: usize = 56;
const PERK_NINJA: usize = 40;
const PERK_HIGHLANDER: usize = 41;
const PERK_ION_GUN_MASTER: usize = 51;

const WEAPON_PISTOL: i64 = 1;
const WEAPON_ASSAULT_RIFLE: i64 = 2;
const WEAPON_SHOTGUN: i64 = 3;
const WEAPON_SAWED_OFF_SHOTGUN: i64 = 4;
const WEAPON_SUBMACHINE_GUN: i64 = 5;
const WEAPON_GAUSS_GUN: i64 = 6;
const WEAPON_MEAN_MINIGUN: i64 = 7;
const WEAPON_FLAMETHROWER: i64 = 8;
const WEAPON_MULTI_PLASMA: i64 = 10;
const WEAPON_ROCKET_LAUNCHER: i64 = 12;
const WEAPON_SEEKER_ROCKETS: i64 = 13;
const WEAPON_PLASMA_SHOTGUN: i64 = 14;
const WEAPON_MINI_ROCKET_SWARMERS: i64 = 17;
const WEAPON_ROCKET_MINIGUN: i64 = 18;
const WEAPON_JACKHAMMER: i64 = 20;
const WEAPON_SHRINKIFIER_5K: i64 = 24;
const WEAPON_GAUSS_SHOTGUN: i64 = 30;
const WEAPON_ION_SHOTGUN: i64 = 31;
const WEAPON_FIRE_BULLETS: i64 = 45;

const BONUS_ID_UNUSED: i32 = 0;
const BONUS_ID_POINTS: i32 = 1;
const BONUS_ID_ENERGIZER: i32 = 2;
const BONUS_ID_WEAPON: i32 = 3;
const BONUS_ID_WEAPON_POWER_UP: i32 = 4;
const BONUS_ID_NUKE: i32 = 5;
const BONUS_ID_DOUBLE_EXPERIENCE: i32 = 6;
const BONUS_ID_SHOCK_CHAIN: i32 = 7;
const BONUS_ID_FIREBLAST: i32 = 8;
const BONUS_ID_REFLEX_BOOST: i32 = 9;
const BONUS_ID_SHIELD: i32 = 10;
const BONUS_ID_FREEZE: i32 = 11;
const BONUS_ID_MEDIKIT: i32 = 12;
const BONUS_ID_SPEED: i32 = 13;
const BONUS_ID_FIRE_BULLETS: i32 = 14;

const BONUS_POOL_SIZE: usize = 16;
const BONUS_SPAWN_MARGIN: f32 = 32.0;
const BONUS_SPAWN_MIN_DISTANCE: f32 = 32.0;
const BONUS_PICKUP_RADIUS: f32 = 26.0;
const BONUS_PICKUP_DECAY_RATE: f32 = 3.0;
const BONUS_PICKUP_LINGER: f32 = 0.5;
const BONUS_TIME_MAX: f32 = 10.0;
const BONUS_WEAPON_NEAR_RADIUS: f32 = 56.0;
const BONUS_AIM_HOVER_RADIUS: f32 = 24.0;
const BONUS_TELEKINETIC_PICKUP_MS: f32 = 650.0;

const BONUS_POINTS_HIGH_CHANCE_MASK: u32 = 7;
const DEATH_SFX_PER_TICK_CAP: i32 = 5;

const PERK_BONUS_MAGNET: usize = 27;
const PERK_TELEKINETIC: usize = 20;
const PERK_BONUS_ECONOMIST: usize = 32;
const PERK_REFLEX_BOOSTED: usize = 44;

const REFLEX_TIMER_SUBTRACT_BIAS: f64 = 4e-9;
const PLAYER_THICK_SKINNED_DAMAGE_SCALE_F32: f32 = f32::from_bits(0x3F2A7EFA);

const PROJECTILE_TYPE_PISTOL: i64 = 0x01;
const PROJECTILE_TYPE_ASSAULT_RIFLE: i64 = 0x02;
const PROJECTILE_TYPE_SHOTGUN: i64 = 0x03;
const PROJECTILE_TYPE_SUBMACHINE_GUN: i64 = 0x05;
const PROJECTILE_TYPE_GAUSS_GUN: i64 = 0x06;
const PROJECTILE_TYPE_PLASMA_RIFLE: i64 = 0x09;
const PROJECTILE_TYPE_PLASMA_MINIGUN: i64 = 0x0B;
const PROJECTILE_TYPE_PULSE_GUN: i64 = 0x13;
const PROJECTILE_TYPE_ION_RIFLE: i64 = 0x15;
const PROJECTILE_TYPE_ION_MINIGUN: i64 = 0x16;
const PROJECTILE_TYPE_ION_CANNON: i64 = 0x17;
const PROJECTILE_TYPE_SHRINKIFIER: i64 = 0x18;
const PROJECTILE_TYPE_BLADE_GUN: i64 = 0x19;
const PROJECTILE_TYPE_SPIDER_PLASMA: i64 = 0x1A;
const PROJECTILE_TYPE_PLASMA_CANNON: i64 = 0x1C;
const PROJECTILE_TYPE_SPLITTER_GUN: i64 = 0x1D;
const PROJECTILE_TYPE_PLAGUE_SPREADER: i64 = 0x29;
const PROJECTILE_TYPE_RAINBOW_GUN: i64 = 0x2B;
const PROJECTILE_TYPE_FIRE_BULLETS: i64 = 0x2D;

const PERK_ID_MAX: usize = 57;

const CREATURE_TYPE_ZOMBIE: i32 = 0;
const CREATURE_TYPE_LIZARD: i32 = 1;
const CREATURE_TYPE_ALIEN: i32 = 2;
const CREATURE_TYPE_SPIDER_SP1: i32 = 3;
const CREATURE_TYPE_SPIDER_SP2: i32 = 4;

const CREATURE_AI_MODE_ORBIT_PLAYER: i32 = 0;
const CREATURE_AI_MODE_ORBIT_PLAYER_TIGHT: i32 = 1;
const CREATURE_AI_MODE_CHASE_PLAYER: i32 = 2;
const CREATURE_AI_MODE_FOLLOW_LINK: i32 = 3;
const CREATURE_AI_MODE_LINK_GUARD: i32 = 4;
const CREATURE_AI_MODE_FOLLOW_LINK_TETHERED: i32 = 5;
const CREATURE_AI_MODE_ORBIT_LINK: i32 = 6;
const CREATURE_AI_MODE_HOLD_TIMER: i32 = 7;
const CREATURE_AI_MODE_ORBIT_PLAYER_WIDE: i32 = 8;
const CREATURE_FLAG_ANIM_PING_PONG: u32 = 0x04;
const CREATURE_FLAG_ANIM_LONG_STRIP: u32 = 0x40;
const CREATURE_FLAG_RANGED_ATTACK_SHOCK: u32 = 0x10;
const CREATURE_FLAG_AI7_LINK_TIMER: u32 = 0x80;
const CREATURE_FLAG_RANGED_ATTACK_VARIANT: u32 = 0x100;
const CREATURE_FLAG_SELF_DAMAGE_TICK: u32 = 0x01;
const CREATURE_FLAG_SELF_DAMAGE_TICK_STRONG: u32 = 0x02;

const SPAWN_ID_SPIDER_SP2_SPLITTER_01: i32 = 0x01;
const SPAWN_ID_FORMATION_RING_ALIEN_8_12: i32 = 0x12;
const SPAWN_ID_ALIEN_CONST_RED_FAST_2B: i32 = 0x2B;
const SPAWN_ID_ALIEN_CONST_RED_BOSS_2C: i32 = 0x2C;
const SPAWN_ID_SPIDER_SP2_RANDOM_35: i32 = 0x35;
const SPAWN_ID_SPIDER_SP1_AI7_TIMER_38: i32 = 0x38;
const SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A: i32 = 0x3A;
const SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C: i32 = 0x3C;

const RANDOM_HEADING_SENTINEL: f32 = -100.0;
const NATIVE_PI: f32 = f32::from_bits(0x40490FDB);
const NATIVE_HALF_PI: f32 = f32::from_bits(0x3FC90FDB);
const NATIVE_TAU: f32 = f32::from_bits(0x40C90FDB);
const NATIVE_TURN_RATE_SCALE: f32 = f32::from_bits(0x3FAAAAAB);
const RELATIVE_MOVE_HEADING_NONE: f32 = -1.0;
const RELATIVE_MOVE_HEADING_FORWARD: f32 = 0.0;
const RELATIVE_MOVE_HEADING_FORWARD_RIGHT: f32 = 0.785_398_2;
const RELATIVE_MOVE_HEADING_RIGHT: f32 = 1.570_796_4;
const RELATIVE_MOVE_HEADING_BACKWARD_RIGHT: f32 = 2.356_194_5;
const RELATIVE_MOVE_HEADING_BACKWARD: f32 = NATIVE_PI;
const RELATIVE_MOVE_HEADING_BACKWARD_LEFT: f32 = 3.926_991;
const RELATIVE_MOVE_HEADING_LEFT: f32 = 4.712_389;
const RELATIVE_MOVE_HEADING_FORWARD_LEFT: f32 = 5.497_787_5;
const RELATIVE_MOVE_TURN_ALIGN_SCALE: f32 = 7.957_747;
const AIM_POINT_RADIUS: f32 = 60.0;
const AIM_KEYBOARD_TURN_RATE: f32 = 3.0;
const AIM_JOYSTICK_TURN_RATE: f32 = 4.0;
const SURVIVAL_SPAWN_EDGE_OFFSET: f32 = 40.0;
const SURVIVAL_RUNTIME_PROJECTILE_MARGIN: f32 = 64.0;
const SURVIVAL_RUNTIME_CREATURE_MARGIN: f32 = 96.0;
const SURVIVAL_RUNTIME_CREATURE_SPEED_SCALE: f32 = 30.0;
const SURVIVAL_RUNTIME_MAX_ENTITIES: usize = 0x180;
const MAIN_PROJECTILE_POOL_SIZE: usize = 0x60;
const CREATURE_LIFECYCLE_ALIVE: f32 = 16.0;
const CREATURE_DEATH_TIMER_DECAY: f32 = 28.0;
const CREATURE_CORPSE_FADE_DECAY: f32 = 20.0;
const CREATURE_CORPSE_DESPAWN_LIFECYCLE: f32 = -10.0;
const CREATURE_DEATH_SLIDE_SCALE: f32 = 9.0;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunResult {
    pub game_mode_id: i64,
    pub tick_rate: i64,
    pub ticks: i64,
    pub elapsed_ms: i64,
    pub score_xp: i64,
    pub creature_kill_count: i64,
    pub most_used_weapon_id: i64,
    pub shots_fired: i64,
    pub shots_hit: i64,
    pub rng_state: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScoreClaimPayload {
    pub metric: String,
    pub submitted_score: i64,
    pub simulated_value: i64,
    #[serde(rename = "match")]
    pub match_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyPayload {
    pub schema_version: i64,
    pub status: String,
    pub replay: String,
    pub replay_sha256: String,
    pub run_result: RunResult,
    pub score_claim: Option<ScoreClaimPayload>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScoreMetric {
    Auto,
    ScoreXp,
    ElapsedMs,
}

impl Default for ScoreMetric {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    #[serde(default)]
    pub submitted_score: Option<i64>,
    #[serde(default)]
    pub score_metric: ScoreMetric,
    #[serde(default)]
    pub replay_label: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("{0}")]
    ReplayCodec(#[from] ReplayCodecError),
    #[error("{0}")]
    ReplayBootstrap(#[from] ReplayBootstrapError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported replay scope: {0}")]
    UnsupportedScope(String),
}

#[derive(Debug, Clone)]
struct PerkSelectionState {
    pending_count: i32,
    choices: Vec<i16>,
    choices_dirty: bool,
}

impl Default for PerkSelectionState {
    fn default() -> Self {
        Self {
            pending_count: 0,
            choices: Vec::new(),
            choices_dirty: true,
        }
    }
}

#[derive(Debug, Clone)]
struct PlayerState {
    size: f32,
    speed_multiplier: f32,
    move_speed: f32,
    move_phase: f32,
    heading: f32,
    turn_speed: f32,
    aim_heading: f32,
    weapon_id: i64,
    clip_size: i64,
    ammo: f32,
    reload_active: bool,
    reload_timer: f32,
    reload_timer_max: f32,
    shot_cooldown: f32,
    spread_heat: f64,
    experience: i64,
    level: i64,
    health: f32,
    aim: Vec2f,
    bonus_aim_hover_index: i32,
    bonus_aim_hover_timer_ms: f32,
    speed_bonus_timer: f32,
    shield_timer: f32,
    fire_bullets_timer: f32,
    alt_weapon_id: Option<i64>,
    perk_counts: [i32; PERK_COUNT_SIZE],
}

impl Default for PlayerState {
    fn default() -> Self {
        Self {
            weapon_id: WEAPON_PISTOL,
            size: 48.0,
            speed_multiplier: 2.0,
            move_speed: 0.0,
            move_phase: 0.0,
            heading: 0.0,
            turn_speed: 1.0,
            aim_heading: 0.0,
            clip_size: 0,
            ammo: 0.0,
            reload_active: false,
            reload_timer: 0.0,
            reload_timer_max: 0.0,
            shot_cooldown: 0.0,
            spread_heat: 0.01,
            experience: 0,
            level: 1,
            health: 100.0,
            aim: Vec2f { x: 0.0, y: 0.0 },
            bonus_aim_hover_index: -1,
            bonus_aim_hover_timer_ms: 0.0,
            speed_bonus_timer: 0.0,
            shield_timer: 0.0,
            fire_bullets_timer: 0.0,
            alt_weapon_id: None,
            perk_counts: [0; PERK_COUNT_SIZE],
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BonusTimers {
    weapon_power_up: f32,
    reflex_boost: f32,
    energizer: f32,
    double_experience: f32,
    freeze: f32,
}

impl Default for BonusTimers {
    fn default() -> Self {
        Self {
            weapon_power_up: 0.0,
            reflex_boost: 0.0,
            energizer: 0.0,
            double_experience: 0.0,
            freeze: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BonusEntry {
    bonus_id: i32,
    picked: bool,
    time_left: f32,
    time_max: f32,
    pos: Vec2f,
    amount: i32,
}

impl Default for BonusEntry {
    fn default() -> Self {
        Self {
            bonus_id: BONUS_ID_UNUSED,
            picked: false,
            time_left: 0.0,
            time_max: 0.0,
            pos: Vec2f { x: 0.0, y: 0.0 },
            amount: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Vec2f {
    x: f32,
    y: f32,
}

impl Vec2f {
    fn add(self, other: Self) -> Self {
        Self {
            x: self.x + other.x,
            y: self.y + other.y,
        }
    }

    fn sub(self, other: Self) -> Self {
        Self {
            x: self.x - other.x,
            y: self.y - other.y,
        }
    }

    fn scale(self, factor: f32) -> Self {
        Self {
            x: self.x * factor,
            y: self.y * factor,
        }
    }

    fn rotated(self, angle: f32) -> Self {
        let cos_theta = angle.cos();
        let sin_theta = angle.sin();
        Self {
            x: self.x * cos_theta - self.y * sin_theta,
            y: self.x * sin_theta + self.y * cos_theta,
        }
    }

    fn length_sq(self) -> f32 {
        self.x * self.x + self.y * self.y
    }

    fn normalized_or_zero(self) -> Self {
        let len_sq = self.length_sq();
        if len_sq <= f32::EPSILON {
            return Self { x: 0.0, y: 0.0 };
        }
        let inv_len = len_sq.sqrt().recip();
        Self {
            x: self.x * inv_len,
            y: self.y * inv_len,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ReplayInputFlags {
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    move_mode: Option<i64>,
    aim_scheme: Option<i64>,
    move_forward_pressed: Option<bool>,
    move_backward_pressed: Option<bool>,
    turn_left_pressed: Option<bool>,
    turn_right_pressed: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
struct SpawnTemplateCall {
    template_id: i32,
    pos: Vec2f,
    heading: f32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct SurvivalSpawnCreature {
    pos: Vec2f,
    heading: f32,
    phase_seed: f32,
    target: Vec2f,
    target_heading: f32,
    force_target: i32,
    target_offset: Vec2f,
    orbit_angle: f32,
    orbit_radius: f32,
    move_scale: f32,
    type_id: i32,
    flags: u32,
    ai_mode: i32,
    link_index: i32,
    health: f32,
    max_health: f32,
    move_speed: f32,
    reward_value: f32,
    size: f32,
    contact_damage: f32,
    lifecycle_stage: f32,
    tint: [f32; 4],
}

#[derive(Debug, Clone, Copy)]
struct RuntimeCreature {
    active: bool,
    pos: Vec2f,
    vel: Vec2f,
    heading: f64,
    target: Vec2f,
    target_heading: f64,
    force_target: i32,
    target_offset: Vec2f,
    orbit_angle: f32,
    orbit_radius: f32,
    phase_seed: f32,
    move_scale: f32,
    type_id: i32,
    flags: u32,
    ai_mode: i32,
    link_index: i32,
    health: f32,
    max_health: f32,
    move_speed: f32,
    reward_value: f32,
    size: f32,
    contact_damage: f32,
    attack_cooldown: f32,
    lifecycle_stage: f32,
    tint: [f32; 4],
}

impl RuntimeCreature {
    fn from_survival_spawn(creature: SurvivalSpawnCreature) -> Self {
        Self {
            active: true,
            pos: creature.pos,
            vel: Vec2f { x: 0.0, y: 0.0 },
            heading: f64::from(creature.heading),
            target: creature.target,
            target_heading: f64::from(creature.target_heading),
            force_target: creature.force_target,
            target_offset: creature.target_offset,
            orbit_angle: creature.orbit_angle,
            orbit_radius: creature.orbit_radius,
            phase_seed: creature.phase_seed,
            move_scale: creature.move_scale,
            type_id: creature.type_id,
            flags: creature.flags,
            ai_mode: creature.ai_mode,
            link_index: creature.link_index,
            health: creature.health,
            max_health: creature.max_health,
            move_speed: creature.move_speed,
            reward_value: creature.reward_value,
            size: creature.size,
            contact_damage: creature.contact_damage,
            attack_cooldown: 0.0,
            lifecycle_stage: creature.lifecycle_stage,
            tint: creature.tint,
        }
    }
}

impl Default for RuntimeCreature {
    fn default() -> Self {
        Self {
            active: false,
            pos: Vec2f { x: 0.0, y: 0.0 },
            vel: Vec2f { x: 0.0, y: 0.0 },
            heading: 0.0,
            target: Vec2f { x: 0.0, y: 0.0 },
            target_heading: 0.0,
            force_target: 0,
            target_offset: Vec2f { x: 0.0, y: 0.0 },
            orbit_angle: 0.0,
            orbit_radius: 0.0,
            phase_seed: 0.0,
            move_scale: 1.0,
            type_id: 0,
            flags: 0,
            ai_mode: 0,
            link_index: -1,
            health: 0.0,
            max_health: 0.0,
            move_speed: 0.0,
            reward_value: 0.0,
            size: 0.0,
            contact_damage: 0.0,
            attack_cooldown: 0.0,
            lifecycle_stage: 0.0,
            tint: [1.0, 1.0, 1.0, 1.0],
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RuntimeProjectile {
    active: bool,
    pos: Vec2f,
    origin: Vec2f,
    angle: f64,
    type_id: i64,
    owner_id: i64,
    hits_players: bool,
    base_damage: f32,
    speed_scale: f32,
    damage_pool: f32,
    hit_radius: f32,
    life_timer: f32,
}

impl Default for RuntimeProjectile {
    fn default() -> Self {
        Self {
            active: false,
            pos: Vec2f { x: 0.0, y: 0.0 },
            origin: Vec2f { x: 0.0, y: 0.0 },
            angle: 0.0,
            type_id: 0,
            owner_id: -100,
            hits_players: false,
            base_damage: 0.0,
            speed_scale: 1.0,
            damage_pool: 1.0,
            hit_radius: 1.0,
            life_timer: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProjectileHitDebug {
    projectile_index: usize,
    creature_index: usize,
    type_id: i64,
    hit_pos: Vec2f,
    target_pos: Vec2f,
    target_size: f32,
}

#[derive(Debug, Clone)]
struct SimState {
    rng: CrtRand,
    game_mode: i64,
    preserve_bugs: bool,
    hardcore: bool,
    detail_preset: i64,
    player_count: i64,
    quest_stage_major: i64,
    quest_stage_minor: i64,
    quest_unlock_index: i64,
    quest_unlock_index_full: i64,

    player: PlayerState,
    perk_selection: PerkSelectionState,
    bonuses: BonusTimers,
    time_scale_active: bool,
    bonus_spawn_guard: bool,
    shock_chain_links_left: i32,
    shock_chain_projectile_id: i32,
    demo_mode_active: bool,
    game_tune_started: bool,
    camera_shake_pulses: i32,
    camera_shake_timer: f32,
    camera_shake_offset: Vec2f,

    perk_available: [bool; PERK_COUNT_SIZE],
    perk_available_unlock_index: i64,
    weapon_available: [bool; WEAPON_COUNT_SIZE],
    weapon_available_game_mode: i64,
    weapon_available_unlock_index: i64,
    weapon_available_unlock_index_full: i64,

    status_weapon_usage_counts: [i64; WEAPON_USAGE_COUNT],

    shots_fired: i64,
    shots_hit: i64,
    weapon_shots_fired: [i64; WEAPON_COUNT_SIZE],
    creature_kill_count: i64,

    survival_spawn_stage: i32,
    survival_spawn_cooldown_ms: f64,
    survival_terrain_width: i32,
    survival_terrain_height: i32,
    player_pos: Vec2f,
    bonus_pool: [BonusEntry; BONUS_POOL_SIZE],
    creatures: Vec<RuntimeCreature>,
    projectiles: Vec<RuntimeProjectile>,
    freeze_corpse_indices_at_tick_start: Vec<bool>,
    pending_creature_phase_death_sfx_draws: i32,
    planned_death_sfx_draws_tick: i32,

    debug_hit_sfx_draws_tick: i64,
    debug_death_sfx_draws_tick: i64,
    debug_bonus_flow_draws_tick: i64,
    debug_weapon_pick_draws_tick: i64,
    debug_projectile_hits_tick: i64,
    debug_projectile_hits_detail_tick: Vec<ProjectileHitDebug>,
    debug_dt_world_tick: f32,
    debug_tick_index: i64,
}

impl SimState {
    fn from_replay(replay: &Replay) -> Self {
        let mut usage = [0_i64; WEAPON_USAGE_COUNT];
        for (idx, value) in replay.header.status.weapon_usage_counts.iter().enumerate() {
            if idx < usage.len() {
                usage[idx] = *value;
            }
        }

        Self {
            rng: CrtRand::new(0),
            game_mode: replay.header.game_mode_id,
            preserve_bugs: replay.header.preserve_bugs,
            hardcore: replay.header.hardcore,
            detail_preset: replay.header.detail_preset,
            player_count: replay.header.player_count,
            quest_stage_major: 0,
            quest_stage_minor: 0,
            quest_unlock_index: replay.header.status.quest_unlock_index,
            quest_unlock_index_full: replay.header.status.quest_unlock_index_full,

            player: PlayerState::default(),
            perk_selection: PerkSelectionState::default(),
            bonuses: BonusTimers::default(),
            time_scale_active: false,
            bonus_spawn_guard: false,
            shock_chain_links_left: 0,
            shock_chain_projectile_id: -1,
            demo_mode_active: false,
            game_tune_started: false,
            camera_shake_pulses: 0,
            camera_shake_timer: 0.0,
            camera_shake_offset: Vec2f { x: 0.0, y: 0.0 },

            perk_available: [false; PERK_COUNT_SIZE],
            perk_available_unlock_index: -1,
            weapon_available: [false; WEAPON_COUNT_SIZE],
            weapon_available_game_mode: -1,
            weapon_available_unlock_index: -1,
            weapon_available_unlock_index_full: -1,

            status_weapon_usage_counts: usage,

            shots_fired: 0,
            shots_hit: 0,
            weapon_shots_fired: [0; WEAPON_COUNT_SIZE],
            creature_kill_count: 0,

            survival_spawn_stage: 0,
            survival_spawn_cooldown_ms: 0.0,
            survival_terrain_width: replay.header.world_size as i32,
            survival_terrain_height: replay.header.world_size as i32,
            player_pos: Vec2f {
                x: replay.header.world_size as f32 * 0.5,
                y: replay.header.world_size as f32 * 0.5,
            },
            bonus_pool: [BonusEntry::default(); BONUS_POOL_SIZE],
            creatures: vec![RuntimeCreature::default(); SURVIVAL_RUNTIME_MAX_ENTITIES],
            projectiles: vec![RuntimeProjectile::default(); MAIN_PROJECTILE_POOL_SIZE],
            freeze_corpse_indices_at_tick_start: Vec::new(),
            pending_creature_phase_death_sfx_draws: 0,
            planned_death_sfx_draws_tick: 0,
            debug_hit_sfx_draws_tick: 0,
            debug_death_sfx_draws_tick: 0,
            debug_bonus_flow_draws_tick: 0,
            debug_weapon_pick_draws_tick: 0,
            debug_projectile_hits_tick: 0,
            debug_projectile_hits_detail_tick: Vec::new(),
            debug_dt_world_tick: 0.0,
            debug_tick_index: -1,
        }
    }
}

pub fn verify_replay_file(
    path: &Path,
    options: VerifyOptions,
) -> Result<VerifyPayload, VerifyError> {
    let bytes = fs::read(path)?;
    let mut opts = options;
    if opts.replay_label.is_none() {
        opts.replay_label = Some(path.to_string_lossy().to_string());
    }
    verify_replay_bytes(&bytes, opts)
}

pub fn verify_replay_bytes(
    bytes: &[u8],
    options: VerifyOptions,
) -> Result<VerifyPayload, VerifyError> {
    let replay_sha256 = sha256_hex(bytes);
    let replay = load_replay(bytes)?;
    enforce_phase1_scope(&replay)?;

    let run_result = simulate_phase1(&replay)?;
    let metric = resolve_score_metric(run_result.game_mode_id, options.score_metric);
    let mut status = "ok".to_string();
    let mut score_claim = None;
    if let Some(submitted_score) = options.submitted_score {
        let simulated_value = if metric == "elapsed_ms" {
            run_result.elapsed_ms
        } else {
            run_result.score_xp
        };
        let match_ok = submitted_score == simulated_value;
        if !match_ok {
            status = "score_mismatch".to_string();
        }
        score_claim = Some(ScoreClaimPayload {
            metric: metric.to_string(),
            submitted_score,
            simulated_value,
            match_ok,
        });
    }

    Ok(VerifyPayload {
        schema_version: REPLAY_VERIFY_SCHEMA_VERSION,
        status,
        replay: options
            .replay_label
            .unwrap_or_else(|| "<bytes>".to_string()),
        replay_sha256,
        run_result,
        score_claim,
    })
}

fn enforce_phase1_scope(replay: &Replay) -> Result<(), VerifyError> {
    if replay.header.game_mode_id != GAME_MODE_SURVIVAL {
        return Err(VerifyError::UnsupportedScope(format!(
            "phase-1 supports survival only (game_mode_id=1), got game_mode_id={}",
            replay.header.game_mode_id
        )));
    }
    if replay.header.player_count != 1 {
        return Err(VerifyError::UnsupportedScope(format!(
            "phase-1 supports 1P only, got player_count={}",
            replay.header.player_count
        )));
    }
    if replay.header.preserve_bugs {
        return Err(VerifyError::UnsupportedScope(
            "phase-1 supports preserve_bugs=false only".to_string(),
        ));
    }
    for event in &replay.events {
        if let ReplayEvent::Unknown(ev) = event {
            return Err(VerifyError::UnsupportedScope(format!(
                "phase-1 does not support replay event kind {:?}",
                ev.kind
            )));
        }
    }
    Ok(())
}

fn simulate_phase1(replay: &Replay) -> Result<RunResult, VerifyError> {
    let tick_rate = replay.header.tick_rate;
    if tick_rate <= 0 {
        return Err(VerifyError::UnsupportedScope(format!(
            "invalid replay tick_rate={} (must be > 0)",
            tick_rate
        )));
    }

    let terrain_edge = terrain_edge_from_world_size(replay.header.world_size)?;
    let mut state = SimState::from_replay(replay);
    state.survival_terrain_width = terrain_edge;
    state.survival_terrain_height = terrain_edge;
    let _ = apply_replay_bootstrap(
        &replay.header,
        &mut state.rng,
        replay.header.world_size,
        true,
    )?;

    weapon_assign_player(&mut state, WEAPON_PISTOL);

    let ticks_total = replay.inputs.len();
    let tick_limit = max_ticks_override_from_env()
        .map(|value| value.min(ticks_total))
        .unwrap_or(ticks_total);
    let mut events_by_tick: Vec<Vec<&ReplayEvent>> = vec![Vec::new(); ticks_total + 1];
    for event in &replay.events {
        let tick = usize::try_from(event.tick_index()).map_err(|_| {
            VerifyError::UnsupportedScope("replay event tick_index conversion failed".to_string())
        })?;
        if tick > ticks_total {
            return Err(VerifyError::UnsupportedScope(format!(
                "replay event tick_index out of bounds: tick={} max={}",
                tick, ticks_total
            )));
        }
        events_by_tick[tick].push(event);
    }

    let dt_frame = (1.0_f32 / tick_rate as f32).max(0.0);
    let mut elapsed_ms: f64 = 0.0;
    let mut trace_writer = open_trace_writer()?;
    let debug_tick = std::env::var("CRIMSON_RUST_DEBUG_TICK")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());

    for tick in 0..tick_limit {
        state.debug_tick_index = i64::try_from(tick).unwrap_or(i64::MAX);
        state.debug_hit_sfx_draws_tick = 0;
        state.debug_death_sfx_draws_tick = 0;
        state.debug_bonus_flow_draws_tick = 0;
        state.debug_weapon_pick_draws_tick = 0;
        state.debug_projectile_hits_tick = 0;
        state.pending_creature_phase_death_sfx_draws = 0;
        state.planned_death_sfx_draws_tick = 0;
        state.debug_projectile_hits_detail_tick.clear();
        state.freeze_corpse_indices_at_tick_start.clear();
        state
            .freeze_corpse_indices_at_tick_start
            .resize(state.creatures.len(), false);
        for idx in 0..state.creatures.len() {
            if state.creatures[idx].active && state.creatures[idx].health <= 0.0 {
                state.freeze_corpse_indices_at_tick_start[idx] = true;
            }
        }
        apply_phase1_events(
            &events_by_tick[tick],
            i64::try_from(tick).unwrap_or(i64::MAX),
            &mut state,
        )?;

        let packed = replay
            .inputs
            .get(tick)
            .and_then(|row| row.first())
            .ok_or_else(|| {
                VerifyError::UnsupportedScope(format!(
                    "replay tick {} missing player-0 input",
                    tick
                ))
            })?;

        let aim = replay_input_aim_or_default(packed, state.player_pos);
        let move_input = replay_input_move_or_zero(packed);
        let input_flags = unpack_input_flags(packed.flags);
        let elapsed_before_ms = elapsed_ms;
        let dt_sim = time_scale_reflex_boost_bonus(
            state.bonuses.reflex_boost,
            state.time_scale_active,
            dt_frame,
        );
        let dt_world = apply_reflex_boosted_dt(dt_sim, &state.player);
        state.debug_dt_world_tick = dt_world;
        let dt_post_player = player_frame_dt_after_roundtrip(
            dt_world,
            state.time_scale_active,
            state.bonuses.reflex_boost,
        );
        if debug_tick == Some(state.debug_tick_index) {
            eprintln!(
                "dbg tick={} rng_before={} dt_sim={} dt_world={} dt_post={}",
                state.debug_tick_index,
                state.rng.state(),
                dt_sim,
                dt_world,
                dt_post_player
            );
        }
        survival_runtime_tick(&mut state, dt_world);
        if debug_tick == Some(state.debug_tick_index) {
            eprintln!(
                "dbg tick={} rng_after_survival_runtime_tick={}",
                state.debug_tick_index,
                state.rng.state()
            );
        }
        tick_player_bonus_timers(&mut state.player, dt_world);
        player_step(&mut state, dt_world, move_input, aim, input_flags);
        if debug_tick == Some(state.debug_tick_index) {
            eprintln!(
                "dbg tick={} rng_after_player_step={}",
                state.debug_tick_index,
                state.rng.state()
            );
        }
        survival_mid_step_spawns(&mut state, f64::from(dt_sim) * 1000.0, elapsed_before_ms);
        if debug_tick == Some(state.debug_tick_index) {
            eprintln!(
                "dbg tick={} rng_after_mid_step_spawns={}",
                state.debug_tick_index,
                state.rng.state()
            );
        }
        camera_shake_update(&mut state, dt_post_player);
        survival_progression_update(&mut state);
        state.time_scale_active = state.bonuses.reflex_boost > 0.0;
        bonus_update_pre_pickup_timers(&mut state.bonuses, dt_post_player);
        bonus_update(&mut state, dt_post_player);
        finalize_post_render_creature_lifecycle(&mut state);
        if debug_tick == Some(state.debug_tick_index) {
            eprintln!(
                "dbg tick={} rng_after_bonus_update={}",
                state.debug_tick_index,
                state.rng.state()
            );
        }

        elapsed_ms += f64::from(dt_sim * 1000.0);
        if let Some(writer) = trace_writer.as_mut() {
            write_trace_row(
                writer,
                i64::try_from(tick).unwrap_or(i64::MAX),
                &state,
                elapsed_ms,
            )?;
        }
    }

    if tick_limit == ticks_total {
        apply_phase1_events(
            &events_by_tick[ticks_total],
            i64::try_from(ticks_total).unwrap_or(i64::MAX),
            &mut state,
        )?;
    }
    if let Some(writer) = trace_writer.as_mut() {
        writer.flush()?;
    }

    let most_used_weapon_id =
        most_used_weapon_id(state.player.weapon_id, &state.weapon_shots_fired);

    Ok(RunResult {
        game_mode_id: replay.header.game_mode_id,
        tick_rate,
        ticks: i64::try_from(tick_limit).unwrap_or(i64::MAX),
        elapsed_ms: elapsed_ms as i64,
        score_xp: state.player.experience,
        creature_kill_count: state.creature_kill_count,
        most_used_weapon_id,
        shots_fired: state.shots_fired,
        shots_hit: state.shots_hit,
        rng_state: u64::from(state.rng.state()),
    })
}

fn apply_phase1_events(
    events: &[&ReplayEvent],
    tick_index: i64,
    state: &mut SimState,
) -> Result<(), VerifyError> {
    let mut menu_open_seen = false;
    for event in events {
        match event {
            ReplayEvent::PerkMenuOpen(_) => {
                // Replay menu-open implies at least one pending perk in live sim.
                if state.perk_selection.pending_count <= 0 {
                    state.perk_selection.pending_count = 1;
                    state.perk_selection.choices_dirty = true;
                }
                let _ = perk_selection_current_choices(state);
                menu_open_seen = true;
            }
            ReplayEvent::PerkPick(ev) => {
                if state.perk_selection.pending_count <= 0 {
                    // Keep replay-driven flow alive even if our simplified XP
                    // model did not set pending perks in the same way.
                    state.perk_selection.pending_count = 1;
                    state.perk_selection.choices_dirty = true;
                }
                let picked = perk_selection_pick(state, ev.choice_index);
                if picked.is_none() {
                    if menu_open_seen && state.perk_selection.pending_count <= 0 {
                        continue;
                    }
                    return Err(VerifyError::UnsupportedScope(format!(
                        "perk_pick failed at tick={} choice_index={}",
                        tick_index, ev.choice_index
                    )));
                }
                let _ = perk_selection_current_choices(state);
            }
            ReplayEvent::Unknown(ev) => {
                return Err(VerifyError::UnsupportedScope(format!(
                    "phase-1 does not support replay event kind {:?}",
                    ev.kind
                )));
            }
        }
    }
    Ok(())
}

fn player_step(
    state: &mut SimState,
    dt: f32,
    move_input: Vec2f,
    aim: Vec2f,
    input_flags: ReplayInputFlags,
) {
    let move_mode = resolve_move_mode_for_update(input_flags, state.demo_mode_active);
    let aim_scheme = resolve_aim_scheme_for_update(input_flags, state.demo_mode_active);
    player_update_position(state, move_input, dt, move_mode, aim_scheme, input_flags);

    let mut angry_reloader_spawn_count = 0_i32;
    let should_start_reload = {
        let player = &mut state.player;

        let cooldown_decay = if state.bonuses.weapon_power_up > 0.0 {
            dt * 1.5
        } else {
            dt
        };
        player.shot_cooldown = (player.shot_cooldown - cooldown_decay).max(0.0);
        if player.shot_cooldown > 0.0 && player.shot_cooldown < 1e-6 {
            player.shot_cooldown = 0.0;
        }

        if perk_active(player, PERK_ANXIOUS_LOADER)
            && input_flags.fire_pressed
            && player.reload_timer > 0.0
        {
            player.reload_timer -= 0.05;
            if player.reload_timer <= 0.0 {
                player.reload_timer = dt * 0.8;
            }
        }

        let reload_preload_underflow = player.reload_timer - dt;
        if player.reload_active && player.reload_timer > 0.0 && reload_preload_underflow <= 1e-7 {
            player.ammo = player.clip_size as f32;
        }

        if player.reload_timer > 0.0 {
            if perk_active(player, PERK_ANGRY_RELOADER)
                && player.reload_timer_max > 0.5
                && (player.reload_timer_max * 0.5) < player.reload_timer
            {
                player.reload_timer -= dt;
                if player.reload_timer <= player.reload_timer_max * 0.5 {
                    let count = 7 + (player.reload_timer_max * 4.0) as i32;
                    if count > 0 {
                        angry_reloader_spawn_count = count;
                    }
                }
            } else {
                player.reload_timer -= dt;
            }
        }

        if player.reload_timer < 0.0 {
            player.reload_timer = 0.0;
        }

        if player.reload_timer <= 0.0 && player.reload_active {
            player.reload_active = false;
            player.ammo = player.clip_size as f32;
        }

        let should_start_reload_local = input_flags.reload_pressed
            && !state.demo_mode_active
            && move_mode != MOVEMENT_CONTROL_TYPE_MOUSE_POINT_CLICK
            && player.reload_timer == 0.0;

        if player.shot_cooldown <= 0.0 && player.reload_timer == 0.0 {
            player.reload_active = false;
        }
        should_start_reload_local
    };
    if angry_reloader_spawn_count > 0 {
        let prev_guard = state.bonus_spawn_guard;
        state.bonus_spawn_guard = true;
        let origin = state.player_pos;
        let angle_step = std::f64::consts::TAU / f64::from(angry_reloader_spawn_count);
        for idx in 0..angry_reloader_spawn_count {
            let angle = f64::from(idx) * angle_step + 0.1_f64;
            let _ = spawn_bonus_projectile(
                state,
                origin,
                angle,
                PROJECTILE_TYPE_PLASMA_MINIGUN,
                None,
                -100,
            );
        }
        state.bonus_spawn_guard = prev_guard;
    }
    if should_start_reload {
        player_start_reload(state);
    }

    player_update_aim_by_scheme(state, aim, dt, move_mode, aim_scheme, input_flags);

    {
        let player = &mut state.player;
        if perk_active(player, PERK_SHARPSHOOTER) {
            player.spread_heat = 0.02;
        } else {
            player.spread_heat = (player.spread_heat - f64::from(dt) * 0.4).max(0.01);
        }
    }

    if input_flags.fire_down {
        let _ = player_fire_weapon(
            state,
            state.player.aim,
            input_flags.fire_down,
            input_flags.fire_pressed,
        );
    }
}

fn player_fire_weapon(
    state: &mut SimState,
    aim: Vec2f,
    fire_down: bool,
    _fire_pressed: bool,
) -> i64 {
    let mut needs_reload_start = false;
    let shot_count: i64;
    let weapon_id: i64;
    let weapon_pellets: i16;
    let is_fire_bullets: bool;
    let mut apply_spread_increase = false;
    let mut spread_inc = 0.0_f32;
    let mut ammo_cost = 1.0_f32;
    {
        let player = &mut state.player;
        let Some(weapon) = weapon_spec(player.weapon_id) else {
            return 0;
        };

        if player.shot_cooldown > 0.0 {
            return 0;
        }
        if !fire_down {
            return 0;
        }
        weapon_id = player.weapon_id;
        weapon_pellets = weapon.pellet_count;
        is_fire_bullets = player.fire_bullets_timer > 0.0;

        if player.reload_timer > 0.0 {
            if player.experience <= 0 {
                return 0;
            }
            if perk_active(player, PERK_REGRESSION_BULLETS) {
                let factor = if weapon.ammo_class == 1 { 4.0 } else { 200.0 };
                let next = (player.experience as f32) - weapon.reload_time_s * factor;
                player.experience = (next as i64).max(0);
            } else if !perk_active(player, PERK_AMMUNITION_WITHIN) {
                return 0;
            }
        }

        let weapon_spread_heat = weapon_spread_heat_inc(weapon_id);
        let fire_bullets_spread_heat = weapon_spread_heat_inc(WEAPON_FIRE_BULLETS);
        let spread_heat_base = if is_fire_bullets {
            fire_bullets_spread_heat
        } else {
            weapon_spread_heat
        };
        spread_inc = spread_heat_base * 1.3;

        let mut shot_cooldown = weapon.shot_cooldown_s;
        if is_fire_bullets && weapon.pellet_count == 1 {
            if let Some(fire_bullets_weapon) = weapon_spec(WEAPON_FIRE_BULLETS) {
                shot_cooldown = fire_bullets_weapon.shot_cooldown_s;
            }
        }
        if perk_active(player, PERK_FASTSHOT) {
            shot_cooldown *= 0.88;
        }
        if perk_active(player, PERK_SHARPSHOOTER) {
            shot_cooldown *= 1.05;
        }
        player.shot_cooldown = shot_cooldown.max(0.0);

        apply_spread_increase = !perk_active(player, PERK_SHARPSHOOTER);
    }

    shot_count = spawn_player_projectiles(state, aim, weapon_id, weapon_pellets);
    if weapon_id == 17 {
        ammo_cost = shot_count as f32;
    }
    state.shots_fired = state.shots_fired.saturating_add(shot_count);
    let weapon_idx = usize::try_from(weapon_id).unwrap_or(0);
    if weapon_idx < state.weapon_shots_fired.len() {
        state.weapon_shots_fired[weapon_idx] =
            state.weapon_shots_fired[weapon_idx].saturating_add(shot_count);
    }

    {
        let player = &mut state.player;
        if apply_spread_increase {
            player.spread_heat = (player.spread_heat + f64::from(spread_inc)).clamp(0.0, 0.48);
        }
        if state.bonuses.reflex_boost <= 0.0 && !is_fire_bullets {
            player.ammo -= ammo_cost;
        }
        if player.ammo <= 0.0 && player.reload_timer <= 0.0 {
            needs_reload_start = true;
        }
    }

    if needs_reload_start {
        player_start_reload(state);
    }
    shot_count
}

fn pellet_jitter_step(weapon_id: i64) -> f32 {
    match weapon_id {
        WEAPON_SHOTGUN | WEAPON_JACKHAMMER => 0.0013,
        WEAPON_SAWED_OFF_SHOTGUN => 0.004,
        _ => 0.0015,
    }
}

fn spawn_single_player_projectile(
    state: &mut SimState,
    pos: Vec2f,
    angle: f64,
    type_id: i64,
    speed_scale: f32,
) -> bool {
    if state.projectiles.is_empty() {
        return false;
    }
    let (base_damage, damage_pool, hit_radius, life_timer) =
        projectile_init_fields_for_type(type_id);
    let slot = state
        .projectiles
        .iter()
        .position(|entry| !entry.active)
        .unwrap_or(state.projectiles.len() - 1);
    state.projectiles[slot] = RuntimeProjectile {
        active: true,
        pos,
        origin: pos,
        angle,
        type_id,
        owner_id: -100,
        hits_players: false,
        base_damage,
        speed_scale,
        damage_pool,
        hit_radius,
        life_timer,
    };
    let debug_tick = std::env::var("CRIMSON_RUST_DEBUG_TICK")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    if debug_tick == Some(state.debug_tick_index) {
        eprintln!(
            "dbg spawn tick={} slot={} type={} pos=({}, {}) angle={}",
            state.debug_tick_index, slot, type_id, pos.x, pos.y, angle
        );
    }
    true
}

fn spawn_player_projectiles(
    state: &mut SimState,
    aim: Vec2f,
    weapon_id: i64,
    pellet_count: i16,
) -> i64 {
    let debug_tick = std::env::var("CRIMSON_RUST_DEBUG_TICK")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    let is_fire_bullets = state.player.fire_bullets_timer > 0.0;
    let spawn_muzzle_after_projectile =
        weapon_spawn_muzzle_after_projectile(weapon_id, is_fire_bullets);
    let aim_delta = aim.sub(state.player_pos);
    let aim_heading =
        f64::from(aim_delta.y).atan2(f64::from(aim_delta.x)) + std::f64::consts::FRAC_PI_2;
    let aim_dir_radians = aim_heading - std::f64::consts::FRAC_PI_2;
    let aim_dir_x = aim_dir_radians.cos();
    let aim_dir_y = aim_dir_radians.sin();
    let rot_angle = -0.150_915_f64;
    let rot_cos = rot_angle.cos();
    let rot_sin = rot_angle.sin();
    let muzzle = Vec2f {
        x: (f64::from(state.player_pos.x) + (aim_dir_x * rot_cos - aim_dir_y * rot_sin) * 16.0)
            as f32,
        y: (f64::from(state.player_pos.y) + (aim_dir_x * rot_sin + aim_dir_y * rot_cos) * 16.0)
            as f32,
    };
    if debug_tick == Some(state.debug_tick_index) {
        eprintln!(
            "dbg fire tick={} player_pos=({:.9}, {:.9}) player_pos_bits=({:#010x}, {:#010x}) heading={:.9} spread={:.9} shot_cd={:.9} aim=({:.9}, {:.9}) aim_bits=({:#010x}, {:#010x}) aim_heading={:.15} muzzle=({:.9}, {:.9})",
            state.debug_tick_index,
            state.player_pos.x,
            state.player_pos.y,
            state.player_pos.x.to_bits(),
            state.player_pos.y.to_bits(),
            state.player.heading,
            state.player.spread_heat,
            state.player.shot_cooldown,
            aim.x,
            aim.y,
            aim.x.to_bits(),
            aim.y.to_bits(),
            aim_heading,
            muzzle.x,
            muzzle.y,
        );
    }
    if weapon_has_shell_casing(weapon_id) {
        // Mirrors `effects.spawn_shell_casing`: angle/speed/rotation/rotation_step draws.
        let _ = state.rng.rand();
        let _ = state.rng.rand();
        let _ = state.rng.rand();
        let _ = state.rng.rand();
    }

    let dist = (f64::from(aim_delta.x) * f64::from(aim_delta.x)
        + f64::from(aim_delta.y) * f64::from(aim_delta.y))
    .sqrt();
    let max_offset = dist * state.player.spread_heat * 0.5;
    let dir_angle = f64::from(state.rng.rand() & 0x1FF) * (std::f64::consts::TAU / 512.0);
    let mag = f64::from(state.rng.rand() & 0x1FF) * (1.0 / 512.0);
    let offset = max_offset * mag;
    let aim_jitter_x = f64::from(aim.x) + dir_angle.cos() * offset;
    let aim_jitter_y = f64::from(aim.y) + dir_angle.sin() * offset;
    let shot_vec_x = aim_jitter_x - f64::from(state.player_pos.x);
    let shot_vec_y = aim_jitter_y - f64::from(state.player_pos.y);
    let shot_angle = shot_vec_y.atan2(shot_vec_x) + std::f64::consts::FRAC_PI_2;
    if debug_tick == Some(state.debug_tick_index) {
        eprintln!(
            "dbg fire tick={} dist={:.15} max_offset={:.15} dir_angle={:.15} mag={:.15} offset={:.15} shot_angle={:.15}",
            state.debug_tick_index,
            dist,
            max_offset,
            dir_angle,
            mag,
            offset,
            shot_angle
        );
    }

    if !is_fire_bullets {
        // Native consumes one draw for shot-SFX variant selection.
        let _ = state.rng.rand();
    }
    if !spawn_muzzle_after_projectile {
        consume_weapon_muzzle_sprite_spawn_rng(state, weapon_id, is_fire_bullets);
    }

    let mut shot_count = 0_i64;

    if is_fire_bullets {
        let pellets = i32::from(pellet_count).max(0);
        for _ in 0..pellets {
            let angle = shot_angle + f64::from((state.rng.rand() % 200) as i32 - 100) * 0.0015;
            if spawn_single_player_projectile(
                state,
                muzzle,
                angle,
                PROJECTILE_TYPE_FIRE_BULLETS,
                1.0,
            ) {
                shot_count += 1;
            }
        }
        if spawn_muzzle_after_projectile {
            consume_weapon_muzzle_sprite_spawn_rng(state, weapon_id, is_fire_bullets);
        }
        return shot_count;
    }

    if weapon_id == WEAPON_MULTI_PLASMA {
        let patterns: [(f64, i64); 5] = [
            (-std::f64::consts::PI * 0.1, PROJECTILE_TYPE_PLASMA_RIFLE),
            (-std::f64::consts::PI / 6.0, PROJECTILE_TYPE_PLASMA_MINIGUN),
            (0.0, PROJECTILE_TYPE_PLASMA_RIFLE),
            (std::f64::consts::PI / 6.0, PROJECTILE_TYPE_PLASMA_MINIGUN),
            (std::f64::consts::PI * 0.1, PROJECTILE_TYPE_PLASMA_RIFLE),
        ];
        for (offset_angle, type_id) in patterns {
            if spawn_single_player_projectile(
                state,
                muzzle,
                shot_angle + offset_angle,
                type_id,
                1.0,
            ) {
                shot_count += 1;
            }
        }
        if spawn_muzzle_after_projectile {
            consume_weapon_muzzle_sprite_spawn_rng(state, weapon_id, is_fire_bullets);
        }
        return shot_count;
    }

    if weapon_id == WEAPON_PLASMA_SHOTGUN {
        for _ in 0..14 {
            let jitter = f64::from((state.rng.rand() & 0xFF) as i32 - 0x80) * 0.002;
            let speed_scale = 1.0 + (state.rng.rand() % 100) as f32 * 0.01;
            if spawn_single_player_projectile(
                state,
                muzzle,
                shot_angle + jitter,
                PROJECTILE_TYPE_PLASMA_MINIGUN,
                speed_scale,
            ) {
                shot_count += 1;
            }
        }
        if spawn_muzzle_after_projectile {
            consume_weapon_muzzle_sprite_spawn_rng(state, weapon_id, is_fire_bullets);
        }
        return shot_count;
    }

    if weapon_id == WEAPON_GAUSS_SHOTGUN {
        for _ in 0..6 {
            let jitter = f64::from((state.rng.rand() % 200) as i32 - 100) * 0.002;
            let speed_scale = 1.4 + (state.rng.rand() % 0x50) as f32 * 0.01;
            if spawn_single_player_projectile(
                state,
                muzzle,
                shot_angle + jitter,
                PROJECTILE_TYPE_GAUSS_GUN,
                speed_scale,
            ) {
                shot_count += 1;
            }
        }
        if spawn_muzzle_after_projectile {
            consume_weapon_muzzle_sprite_spawn_rng(state, weapon_id, is_fire_bullets);
        }
        return shot_count;
    }

    if weapon_id == WEAPON_ION_SHOTGUN {
        for _ in 0..8 {
            let jitter = f64::from((state.rng.rand() % 200) as i32 - 100) * 0.0026;
            let speed_scale = 1.4 + (state.rng.rand() % 0x50) as f32 * 0.01;
            if spawn_single_player_projectile(
                state,
                muzzle,
                shot_angle + jitter,
                PROJECTILE_TYPE_ION_MINIGUN,
                speed_scale,
            ) {
                shot_count += 1;
            }
        }
        if spawn_muzzle_after_projectile {
            consume_weapon_muzzle_sprite_spawn_rng(state, weapon_id, is_fire_bullets);
        }
        return shot_count;
    }

    let Some(type_id) = projectile_type_id_from_weapon_id(weapon_id) else {
        return 0;
    };
    let pellets = i32::from(pellet_count).max(1);
    let jitter_step = f64::from(pellet_jitter_step(weapon_id));
    for _ in 0..pellets {
        let mut angle = shot_angle;
        if pellets > 1 {
            angle += f64::from((state.rng.rand() % 200) as i32 - 100) * jitter_step;
        }
        let mut speed_scale = 1.0;
        if pellets > 1
            && matches!(
                weapon_id,
                WEAPON_SHOTGUN | WEAPON_SAWED_OFF_SHOTGUN | WEAPON_JACKHAMMER
            )
        {
            speed_scale = 1.0 + (state.rng.rand() % 100) as f32 * 0.01;
        }
        if spawn_single_player_projectile(state, muzzle, angle, type_id, speed_scale) {
            shot_count += 1;
        }
    }
    if spawn_muzzle_after_projectile {
        consume_weapon_muzzle_sprite_spawn_rng(state, weapon_id, is_fire_bullets);
    }
    shot_count
}

fn weapon_spawn_muzzle_after_projectile(weapon_id: i64, fire_bullets_active: bool) -> bool {
    fire_bullets_active || matches!(weapon_id, WEAPON_PISTOL | WEAPON_SHRINKIFIER_5K)
}

fn weapon_muzzle_sprite_spawn_count(weapon_id: i64, fire_bullets_active: bool) -> i32 {
    if fire_bullets_active {
        return 1;
    }
    match weapon_id {
        WEAPON_PISTOL
        | WEAPON_ASSAULT_RIFLE
        | WEAPON_SHOTGUN
        | WEAPON_SAWED_OFF_SHOTGUN
        | WEAPON_SUBMACHINE_GUN
        | WEAPON_GAUSS_GUN
        | WEAPON_ROCKET_LAUNCHER
        | WEAPON_SEEKER_ROCKETS
        | WEAPON_MINI_ROCKET_SWARMERS
        | WEAPON_SHRINKIFIER_5K
        | WEAPON_GAUSS_SHOTGUN => 2,
        WEAPON_ROCKET_MINIGUN | WEAPON_JACKHAMMER => 1,
        _ => 0,
    }
}

fn consume_weapon_muzzle_sprite_spawn_rng(
    state: &mut SimState,
    weapon_id: i64,
    fire_bullets_active: bool,
) {
    let count = weapon_muzzle_sprite_spawn_count(weapon_id, fire_bullets_active);
    for _ in 0..count {
        // `fx_spawn_sprite` consumes one draw for rotation for each spawned sprite.
        let _ = state.rng.rand();
    }
}

fn weapon_has_shell_casing(weapon_id: i64) -> bool {
    matches!(
        weapon_id,
        WEAPON_PISTOL
            | WEAPON_ASSAULT_RIFLE
            | WEAPON_SHOTGUN
            | WEAPON_SAWED_OFF_SHOTGUN
            | WEAPON_SUBMACHINE_GUN
            | WEAPON_JACKHAMMER
            | WEAPON_GAUSS_SHOTGUN
            | WEAPON_ION_SHOTGUN
            | WEAPON_FIRE_BULLETS
            | 6
            | 7
            | 50
            | 51
    )
}

fn weapon_spread_heat_inc(weapon_id: i64) -> f32 {
    match weapon_id {
        1 => 0.22,
        2 => 0.09,
        3 => 0.27,
        4 => 0.13,
        5 => 0.082,
        6 => 0.42,
        7 => 0.062,
        8 => 0.015,
        9 => 0.182,
        10 => 0.32,
        11 => 0.097,
        12 => 0.42,
        13 => 0.32,
        14 => 0.11,
        15 => 0.01,
        16 => 0.01,
        17 => 0.12,
        18 => 0.12,
        19 => 0.0,
        20 => 0.16,
        21 => 0.112,
        22 => 0.09,
        23 => 0.68,
        24 => 0.04,
        25 => 0.04,
        26 => 0.04,
        27 => 0.68,
        28 => 0.6,
        29 => 0.28,
        30 => 0.27,
        31 => 0.27,
        32 => 0.18,
        33 => 0.38,
        41 => 0.04,
        42 => 0.05,
        43 => 0.09,
        44 => 0.4,
        45 => 0.22,
        50 => 0.04,
        51 => 0.05,
        52 => 1.0,
        53 => 1.0,
        _ => 0.0,
    }
}

fn projectile_type_id_from_weapon_id(weapon_id: i64) -> Option<i64> {
    match weapon_id {
        WEAPON_SAWED_OFF_SHOTGUN | WEAPON_JACKHAMMER => Some(PROJECTILE_TYPE_SHOTGUN),
        WEAPON_MULTI_PLASMA => Some(PROJECTILE_TYPE_PLASMA_RIFLE),
        WEAPON_PLASMA_SHOTGUN => Some(PROJECTILE_TYPE_PLASMA_MINIGUN),
        WEAPON_GAUSS_SHOTGUN => Some(PROJECTILE_TYPE_GAUSS_GUN),
        WEAPON_ION_SHOTGUN => Some(PROJECTILE_TYPE_ION_MINIGUN),
        id if id > 0 => Some(id),
        _ => None,
    }
}

fn projectile_init_fields_for_type(type_id: i64) -> (f32, f32, f32, f32) {
    let base_damage = projectile_base_damage_for_type(type_id);
    let life_timer = 0.4;
    if type_id == PROJECTILE_TYPE_ION_MINIGUN {
        return (base_damage, 1.0, 3.0, life_timer);
    }
    if type_id == PROJECTILE_TYPE_ION_RIFLE {
        return (base_damage, 1.0, 5.0, life_timer);
    }
    if type_id == PROJECTILE_TYPE_ION_CANNON || type_id == PROJECTILE_TYPE_PLASMA_CANNON {
        return (base_damage, 1.0, 10.0, life_timer);
    }
    if type_id == PROJECTILE_TYPE_GAUSS_GUN {
        return (base_damage, 300.0, 1.0, life_timer);
    }
    if type_id == PROJECTILE_TYPE_FIRE_BULLETS {
        return (base_damage, 240.0, 1.0, life_timer);
    }
    if type_id == PROJECTILE_TYPE_BLADE_GUN {
        return (base_damage, 50.0, 1.0, life_timer);
    }
    (base_damage, 1.0, 1.0, life_timer)
}

fn projectile_base_damage_for_type(type_id: i64) -> f32 {
    match type_id {
        PROJECTILE_TYPE_PISTOL => 55.0,
        PROJECTILE_TYPE_ASSAULT_RIFLE => 50.0,
        PROJECTILE_TYPE_SHOTGUN => 60.0,
        PROJECTILE_TYPE_SUBMACHINE_GUN => 45.0,
        PROJECTILE_TYPE_GAUSS_GUN => 215.0,
        PROJECTILE_TYPE_PLASMA_RIFLE => 30.0,
        PROJECTILE_TYPE_PLASMA_MINIGUN => 35.0,
        PROJECTILE_TYPE_PULSE_GUN => 20.0,
        PROJECTILE_TYPE_ION_RIFLE => 15.0,
        PROJECTILE_TYPE_ION_MINIGUN => 20.0,
        PROJECTILE_TYPE_ION_CANNON => 10.0,
        PROJECTILE_TYPE_SHRINKIFIER => 45.0,
        PROJECTILE_TYPE_BLADE_GUN => 20.0,
        PROJECTILE_TYPE_SPIDER_PLASMA => 10.0,
        PROJECTILE_TYPE_PLASMA_CANNON => 10.0,
        PROJECTILE_TYPE_SPLITTER_GUN => 30.0,
        PROJECTILE_TYPE_PLAGUE_SPREADER => 15.0,
        PROJECTILE_TYPE_RAINBOW_GUN => 10.0,
        PROJECTILE_TYPE_FIRE_BULLETS => 60.0,
        _ => 45.0,
    }
}

fn projectile_damage_scale_for_type(type_id: i64) -> f32 {
    match type_id {
        PROJECTILE_TYPE_PISTOL => 4.1,
        PROJECTILE_TYPE_ASSAULT_RIFLE => 1.0,
        PROJECTILE_TYPE_SHOTGUN => 1.2,
        PROJECTILE_TYPE_SUBMACHINE_GUN => 1.0,
        PROJECTILE_TYPE_GAUSS_GUN => 1.0,
        PROJECTILE_TYPE_PLASMA_RIFLE => 5.0,
        PROJECTILE_TYPE_PLASMA_MINIGUN => 2.1,
        PROJECTILE_TYPE_PULSE_GUN => 1.0,
        PROJECTILE_TYPE_ION_RIFLE => 3.0,
        PROJECTILE_TYPE_ION_MINIGUN => 1.4,
        PROJECTILE_TYPE_ION_CANNON => 16.7,
        PROJECTILE_TYPE_SHRINKIFIER => 0.0,
        PROJECTILE_TYPE_BLADE_GUN => 11.0,
        PROJECTILE_TYPE_SPIDER_PLASMA => 0.5,
        PROJECTILE_TYPE_PLASMA_CANNON => 28.0,
        PROJECTILE_TYPE_SPLITTER_GUN => 6.0,
        PROJECTILE_TYPE_PLAGUE_SPREADER => 0.0,
        PROJECTILE_TYPE_RAINBOW_GUN => 1.0,
        PROJECTILE_TYPE_FIRE_BULLETS => 0.25,
        _ => 1.0,
    }
}

fn projectile_is_piercing_type(type_id: i64) -> bool {
    matches!(
        type_id,
        PROJECTILE_TYPE_FIRE_BULLETS | PROJECTILE_TYPE_GAUSS_GUN | PROJECTILE_TYPE_BLADE_GUN
    )
}

fn player_start_reload(state: &mut SimState) {
    let player = &mut state.player;
    if player.reload_active
        && (perk_active(player, PERK_AMMUNITION_WITHIN)
            || perk_active(player, PERK_REGRESSION_BULLETS))
    {
        return;
    }

    let Some(weapon) = weapon_spec(player.weapon_id) else {
        return;
    };

    let mut reload_time = weapon.reload_time_s;
    if perk_active(player, PERK_FASTLOADER) {
        reload_time *= 0.7;
    }
    if state.bonuses.weapon_power_up > 0.0 {
        reload_time *= 0.6;
    }

    if !player.reload_active {
        player.reload_active = true;
    }
    player.reload_timer = reload_time.max(0.0);
    player.reload_timer_max = player.reload_timer;
}

fn weapon_assign_player(state: &mut SimState, weapon_id: i64) {
    let player = &mut state.player;
    player.weapon_id = weapon_id;
    let usage_idx = usize::try_from(weapon_id.max(0)).unwrap_or(0);
    if usage_idx < state.status_weapon_usage_counts.len() {
        state.status_weapon_usage_counts[usage_idx] =
            state.status_weapon_usage_counts[usage_idx].saturating_add(1);
    }

    let mut clip_size =
        weapon_spec(weapon_id).map_or(0_i64, |entry| i64::from(entry.clip_size).max(0));
    if perk_active(player, PERK_AMMO_MANIAC) {
        clip_size += ((clip_size as f32) * 0.25).floor() as i64;
        if clip_size < 1 {
            clip_size = 1;
        }
    }
    if perk_active(player, PERK_MY_FAVOURITE_WEAPON) {
        clip_size += 2;
    }

    player.clip_size = clip_size.max(0);
    player.ammo = player.clip_size as f32;
    player.reload_active = false;
    player.reload_timer = 0.0;
    player.reload_timer_max = 0.0;
    player.shot_cooldown = 0.0;
}

fn survival_mid_step_spawns(state: &mut SimState, frame_dt_ms: f64, survival_elapsed_ms: f64) {
    let (stage, milestone_calls) =
        advance_survival_spawn_stage(state.survival_spawn_stage, state.player.level);
    state.survival_spawn_stage = stage;

    for call in milestone_calls {
        materialize_survival_stage_template_spawn(state, call);
    }

    let player_count = i32::try_from(state.player_count).unwrap_or(1);
    let player_experience = state.player.experience;
    let terrain_width = state.survival_terrain_width;
    let terrain_height = state.survival_terrain_height;
    let (cooldown, wave_spawns) = tick_survival_wave_spawns(
        state.survival_spawn_cooldown_ms,
        frame_dt_ms,
        &mut state.rng,
        player_count,
        survival_elapsed_ms,
        player_experience,
        terrain_width,
        terrain_height,
    );
    state.survival_spawn_cooldown_ms = cooldown;
    for spawn in wave_spawns {
        runtime_spawn_survival_creature(state, spawn);
    }
}

fn tick_survival_wave_spawns(
    spawn_cooldown: f64,
    frame_dt_ms: f64,
    rng: &mut CrtRand,
    player_count: i32,
    survival_elapsed_ms: f64,
    player_experience: i64,
    terrain_width: i32,
    terrain_height: i32,
) -> (f64, Vec<SurvivalSpawnCreature>) {
    let mut cooldown = spawn_cooldown - (player_count as f64) * frame_dt_ms;
    if cooldown > -1.0 {
        return (cooldown, Vec::new());
    }

    let mut interval_ms = 500 - (survival_elapsed_ms as i32) / 1800;
    let mut spawns: Vec<SurvivalSpawnCreature> = Vec::new();

    if interval_ms < 0 {
        let extra = (1 - interval_ms) >> 1;
        interval_ms += extra * 2;
        for _ in 0..usize::try_from(extra.max(0)).unwrap_or(0) {
            let pos = rand_survival_spawn_pos(rng, terrain_width, terrain_height);
            spawns.push(build_survival_spawn_creature(pos, rng, player_experience));
        }
    }

    if interval_ms < 1 {
        interval_ms = 1;
    }
    cooldown += interval_ms as f64;

    let pos = rand_survival_spawn_pos(rng, terrain_width, terrain_height);
    spawns.push(build_survival_spawn_creature(pos, rng, player_experience));

    (cooldown, spawns)
}

fn advance_survival_spawn_stage(
    mut stage: i32,
    player_level: i64,
) -> (i32, Vec<SpawnTemplateCall>) {
    let level = i32::try_from(player_level).unwrap_or(i32::MAX);
    let heading = std::f32::consts::PI;
    let mut spawns: Vec<SpawnTemplateCall> = Vec::new();

    loop {
        if stage == 0 {
            if level < 5 {
                break;
            }
            stage = 1;
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_FORMATION_RING_ALIEN_8_12,
                pos: Vec2f {
                    x: -164.0,
                    y: 512.0,
                },
                heading,
            });
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_FORMATION_RING_ALIEN_8_12,
                pos: Vec2f {
                    x: 1188.0,
                    y: 512.0,
                },
                heading,
            });
            continue;
        }

        if stage == 1 {
            if level < 9 {
                break;
            }
            stage = 2;
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_ALIEN_CONST_RED_BOSS_2C,
                pos: Vec2f {
                    x: 1088.0,
                    y: 512.0,
                },
                heading,
            });
            continue;
        }

        if stage == 2 {
            if level < 11 {
                break;
            }
            stage = 3;
            let step = 128.0_f32 / 3.0_f32;
            for i in 0..12 {
                spawns.push(SpawnTemplateCall {
                    template_id: SPAWN_ID_SPIDER_SP2_RANDOM_35,
                    pos: Vec2f {
                        x: 1088.0,
                        y: (i as f32) * step + 256.0,
                    },
                    heading,
                });
            }
            continue;
        }

        if stage == 3 {
            if level < 13 {
                break;
            }
            stage = 4;
            for i in 0..4 {
                spawns.push(SpawnTemplateCall {
                    template_id: SPAWN_ID_ALIEN_CONST_RED_FAST_2B,
                    pos: Vec2f {
                        x: 1088.0,
                        y: (i as f32) * 64.0 + 384.0,
                    },
                    heading,
                });
            }
            continue;
        }

        if stage == 4 {
            if level < 15 {
                break;
            }
            stage = 5;
            for i in 0..4 {
                spawns.push(SpawnTemplateCall {
                    template_id: SPAWN_ID_SPIDER_SP1_AI7_TIMER_38,
                    pos: Vec2f {
                        x: 1088.0,
                        y: (i as f32) * 64.0 + 384.0,
                    },
                    heading,
                });
            }
            for i in 0..4 {
                spawns.push(SpawnTemplateCall {
                    template_id: SPAWN_ID_SPIDER_SP1_AI7_TIMER_38,
                    pos: Vec2f {
                        x: -64.0,
                        y: (i as f32) * 64.0 + 384.0,
                    },
                    heading,
                });
            }
            continue;
        }

        if stage == 5 {
            if level < 17 {
                break;
            }
            stage = 6;
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
                pos: Vec2f {
                    x: 1088.0,
                    y: 512.0,
                },
                heading,
            });
            continue;
        }

        if stage == 6 {
            if level < 19 {
                break;
            }
            stage = 7;
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_SPIDER_SP2_SPLITTER_01,
                pos: Vec2f { x: 640.0, y: 512.0 },
                heading,
            });
            continue;
        }

        if stage == 7 {
            if level < 21 {
                break;
            }
            stage = 8;
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_SPIDER_SP2_SPLITTER_01,
                pos: Vec2f { x: 384.0, y: 256.0 },
                heading,
            });
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_SPIDER_SP2_SPLITTER_01,
                pos: Vec2f { x: 640.0, y: 768.0 },
                heading,
            });
            continue;
        }

        if stage == 8 {
            if level < 26 {
                break;
            }
            stage = 9;
            for i in 0..4 {
                spawns.push(SpawnTemplateCall {
                    template_id: SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                    pos: Vec2f {
                        x: 1088.0,
                        y: (i as f32) * 64.0 + 384.0,
                    },
                    heading,
                });
            }
            for i in 0..4 {
                spawns.push(SpawnTemplateCall {
                    template_id: SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                    pos: Vec2f {
                        x: -64.0,
                        y: (i as f32) * 64.0 + 384.0,
                    },
                    heading,
                });
            }
            continue;
        }

        if stage == 9 {
            if level <= 31 {
                break;
            }
            stage = 10;
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
                pos: Vec2f {
                    x: 1088.0,
                    y: 512.0,
                },
                heading,
            });
            spawns.push(SpawnTemplateCall {
                template_id: SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
                pos: Vec2f { x: -64.0, y: 512.0 },
                heading,
            });
            for i in 0..4 {
                spawns.push(SpawnTemplateCall {
                    template_id: SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                    pos: Vec2f {
                        x: (i as f32) * 64.0 + 384.0,
                        y: -64.0,
                    },
                    heading,
                });
            }
            for i in 0..4 {
                spawns.push(SpawnTemplateCall {
                    template_id: SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                    pos: Vec2f {
                        x: (i as f32) * 64.0 + 384.0,
                        y: 1088.0,
                    },
                    heading,
                });
            }
            continue;
        }

        break;
    }

    (stage, spawns)
}

fn rand_survival_spawn_pos(rng: &mut CrtRand, terrain_width: i32, terrain_height: i32) -> Vec2f {
    let width = u32::try_from(terrain_width.max(1)).unwrap_or(1);
    let height = u32::try_from(terrain_height.max(1)).unwrap_or(1);
    match rng.rand() & 3 {
        0 => Vec2f {
            x: (rng.rand() % width) as f32,
            y: -SURVIVAL_SPAWN_EDGE_OFFSET,
        },
        1 => Vec2f {
            x: (rng.rand() % width) as f32,
            y: terrain_height as f32 + SURVIVAL_SPAWN_EDGE_OFFSET,
        },
        2 => Vec2f {
            x: -SURVIVAL_SPAWN_EDGE_OFFSET,
            y: (rng.rand() % height) as f32,
        },
        _ => Vec2f {
            x: terrain_width as f32 + SURVIVAL_SPAWN_EDGE_OFFSET,
            y: (rng.rand() % height) as f32,
        },
    }
}

fn build_survival_spawn_creature(
    pos: Vec2f,
    rng: &mut CrtRand,
    player_experience: i64,
) -> SurvivalSpawnCreature {
    let xp = player_experience;
    let mut creature = alloc_survival_spawn_creature(pos, rng);
    creature.ai_mode = CREATURE_AI_MODE_ORBIT_PLAYER;

    let r10 = rng.rand() % 10;
    let mut type_id: i32;

    if xp < 12_000 {
        type_id = if r10 < 9 {
            CREATURE_TYPE_ALIEN
        } else {
            CREATURE_TYPE_SPIDER_SP1
        };
    } else if xp < 25_000 {
        type_id = if r10 < 4 {
            CREATURE_TYPE_ZOMBIE
        } else {
            CREATURE_TYPE_SPIDER_SP1
        };
        if 8 < r10 {
            type_id = CREATURE_TYPE_ALIEN;
        }
    } else if xp < 42_000 {
        if r10 < 5 {
            type_id = CREATURE_TYPE_ALIEN;
        } else {
            type_id = (rng.rand() & 1) as i32 + 3;
        }
    } else if xp < 50_000 {
        type_id = CREATURE_TYPE_ALIEN;
    } else if xp < 90_000 {
        type_id = CREATURE_TYPE_SPIDER_SP2;
    } else if 109_999 < xp {
        if r10 < 6 {
            type_id = CREATURE_TYPE_ALIEN;
        } else if r10 < 9 {
            type_id = CREATURE_TYPE_SPIDER_SP2;
        } else {
            type_id = CREATURE_TYPE_ZOMBIE;
        }
    } else {
        type_id = CREATURE_TYPE_ZOMBIE;
    }

    if (rng.rand() & 0x1F) == 2 {
        type_id = CREATURE_TYPE_SPIDER_SP1;
    }

    creature.type_id = type_id;
    creature.size = (rng.rand() % 20 + 44) as f32;
    creature.heading = (rng.rand() % 314) as f32 * 0.01;

    let mut move_speed = (xp / 4000) as f32 * 0.045 + 0.9;
    if creature.type_id == CREATURE_TYPE_SPIDER_SP1 {
        creature.flags |= CREATURE_FLAG_AI7_LINK_TIMER;
        move_speed = move_speed * 1.3;
    }

    let r_health = rng.rand();
    let mut health = xp as f32 * 0.00125 + (r_health & 0xF) as f32 + 52.0;

    if creature.type_id == CREATURE_TYPE_ZOMBIE {
        move_speed = move_speed * 0.6;
        if move_speed < 1.3 {
            move_speed = 1.3;
        }
        health = health * 1.5;
    }
    if 3.5 < move_speed {
        move_speed = 3.5;
    }

    creature.move_speed = move_speed;
    creature.health = health;
    creature.reward_value = 0.0;

    let tint_r: f32;
    let tint_g: f32;
    let mut tint_b: f32;
    let tint_a = 1.0;

    if xp < 50_000 {
        tint_r = 1.0 - 1.0 / ((xp / 1000) as f32 + 10.0);
        tint_g = (rng.rand() % 10) as f32 * 0.01 + 0.9 - 1.0 / ((xp / 10_000) as f32 + 10.0);
        tint_b = (rng.rand() % 10) as f32 * 0.01 + 0.7;
    } else if xp < 100_000 {
        tint_r = 0.9 - 1.0 / ((xp / 1000) as f32 + 10.0);
        tint_g = (rng.rand() % 10) as f32 * 0.01 + 0.8 - 1.0 / ((xp / 10_000) as f32 + 10.0);
        tint_b = (xp - 50_000) as f32 * 0.000_006 + (rng.rand() % 10) as f32 * 0.01 + 0.7;
    } else {
        tint_r = 1.0 - 1.0 / ((xp / 1000) as f32 + 10.0);
        tint_g = (rng.rand() % 10) as f32 * 0.01 + 0.9 - 1.0 / ((xp / 10_000) as f32 + 10.0);
        tint_b = (rng.rand() % 10) as f32 * 0.01 + 1.0 - (xp - 100_000) as f32 * 0.000_003;
        if tint_b < 0.5 {
            tint_b = 0.5;
        }
    }
    creature.tint = [tint_r, tint_g, tint_b, tint_a];

    creature.contact_damage = creature.size * (2.0 / 21.0);
    creature.reward_value = creature.health * 0.4
        + creature.contact_damage * 0.8
        + move_speed * 5.0
        + (rng.rand() % 10 + 10) as f32;

    let mut r = rng.rand();
    if r % 180 < 2 {
        creature.tint = [0.9, 0.4, 0.4, 1.0];
        creature.health = 65.0;
        creature.reward_value = 320.0;
    } else {
        r = rng.rand();
        if r % 240 < 2 {
            creature.tint = [0.4, 0.9, 0.4, 1.0];
            creature.health = 85.0;
            creature.reward_value = 420.0;
        } else {
            r = rng.rand();
            if r % 360 < 2 {
                creature.tint = [0.4, 0.4, 0.9, 1.0];
                creature.health = 125.0;
                creature.reward_value = 520.0;
            }
        }
    }

    r = rng.rand();
    if r % 1320 < 4 {
        creature.tint = [0.84, 0.24, 0.89, 1.0];
        creature.size = 80.0;
        creature.reward_value = 600.0;
        creature.health += 230.0;
    } else {
        r = rng.rand();
        if r % 1620 < 4 {
            creature.tint = [0.94, 0.84, 0.29, 1.0];
            creature.size = 85.0;
            creature.reward_value = 900.0;
            creature.health += 2230.0;
        }
    }

    creature.max_health = creature.health;
    creature.reward_value *= 0.8;
    creature.tint = [
        clamp01(creature.tint[0]),
        clamp01(creature.tint[1]),
        clamp01(creature.tint[2]),
        clamp01(creature.tint[3]),
    ];

    creature
}

fn materialize_survival_stage_template_spawn(state: &mut SimState, call: SpawnTemplateCall) {
    // Ring-formation template consumes and uses alloc-time draws inline while
    // materializing children (phase_seed + stale-heading preservation).
    if call.template_id != SPAWN_ID_FORMATION_RING_ALIEN_8_12 {
        consume_survival_template_build_rng(&mut state.rng, call.template_id, call.heading);
    }
    spawn_survival_template_runtime_creatures(state, call);

    if call.pos.x > 0.0
        && call.pos.x < state.survival_terrain_width as f32
        && call.pos.y > 0.0
        && call.pos.y < state.survival_terrain_height as f32
    {
        consume_spawn_burst_rng(&mut state.rng, 8);
    }
}

fn runtime_alloc_creature_slot(state: &mut SimState) -> Option<usize> {
    for idx in 0..state.creatures.len() {
        if !state.creatures[idx].active {
            return Some(idx);
        }
    }
    if state.creatures.is_empty() {
        return None;
    }
    Some((state.rng.rand() as usize) % state.creatures.len())
}

fn runtime_spawn_survival_creature(state: &mut SimState, creature: SurvivalSpawnCreature) {
    let Some(slot_idx) = runtime_alloc_creature_slot(state) else {
        return;
    };
    let stale_target_heading = state.creatures[slot_idx].target_heading;
    let stale_link_index = state.creatures[slot_idx].link_index;
    let mut entry = RuntimeCreature::from_survival_spawn(creature);
    // Native spawn paths do not refresh target_heading; keep recycled-slot value.
    entry.target_heading = stale_target_heading;
    // Native survival spawn paths keep stale link_index from the recycled slot.
    entry.link_index = stale_link_index;
    state.creatures[slot_idx] = entry;
}

fn runtime_spawn_template_creature(
    state: &mut SimState,
    pos: Vec2f,
    heading: f32,
    type_id: i32,
    flags: u32,
    ai_mode: i32,
    health: f32,
    move_speed: f32,
    reward_value: f32,
    size: f32,
    contact_damage: f32,
    tint: [f32; 4],
) -> i32 {
    let Some(slot_idx) = runtime_alloc_creature_slot(state) else {
        return -1;
    };
    let stale_target_heading = state.creatures[slot_idx].target_heading;
    let stale_link_index = state.creatures[slot_idx].link_index;
    state.creatures[slot_idx] = RuntimeCreature {
        active: true,
        pos,
        vel: Vec2f { x: 0.0, y: 0.0 },
        heading: f64::from(heading),
        target: pos,
        // Native spawn paths write heading but leave target_heading stale.
        target_heading: stale_target_heading,
        force_target: 0,
        target_offset: Vec2f { x: 0.0, y: 0.0 },
        orbit_angle: 0.0,
        orbit_radius: 0.0,
        phase_seed: 0.0,
        move_scale: 1.0,
        type_id,
        flags,
        ai_mode,
        link_index: stale_link_index,
        health,
        max_health: health,
        move_speed,
        reward_value,
        size,
        contact_damage,
        attack_cooldown: 0.0,
        lifecycle_stage: CREATURE_LIFECYCLE_ALIVE,
        tint,
    };
    i32::try_from(slot_idx).unwrap_or(-1)
}

fn spawn_survival_template_runtime_creatures(state: &mut SimState, call: SpawnTemplateCall) {
    match call.template_id {
        SPAWN_ID_SPIDER_SP2_SPLITTER_01 => {
            runtime_spawn_template_creature(
                state,
                call.pos,
                call.heading,
                CREATURE_TYPE_SPIDER_SP2,
                0,
                CREATURE_AI_MODE_ORBIT_PLAYER,
                400.0,
                2.0,
                1000.0,
                80.0,
                17.0,
                [0.8, 0.7, 0.4, 1.0],
            );
        }
        SPAWN_ID_FORMATION_RING_ALIEN_8_12 => {
            let base_phase_seed = (state.rng.rand() & 0x17F) as f32;
            let mut final_heading = call.heading;
            if call.heading == RANDOM_HEADING_SENTINEL {
                final_heading = (state.rng.rand() % 628) as f32 * 0.01;
            }
            // Native seeds a transient base heading before tail rewrites the
            // template primary (which, for ring formations, is the last child).
            let base_heading = (state.rng.rand() % 314) as f32 * 0.01;

            let parent_idx = runtime_spawn_template_creature(
                state,
                call.pos,
                base_heading,
                CREATURE_TYPE_ALIEN,
                0,
                CREATURE_AI_MODE_ORBIT_PLAYER,
                200.0,
                2.2,
                600.0,
                55.0,
                14.0,
                [0.65, 0.85, 0.97, 1.0],
            );
            if let Ok(parent_slot) = usize::try_from(parent_idx) {
                if parent_slot < state.creatures.len() {
                    state.creatures[parent_slot].phase_seed = base_phase_seed;
                }
            }
            let angle_step = std::f32::consts::PI / 4.0;
            for idx in 0..8 {
                let child_phase_seed = (state.rng.rand() & 0x17F) as f32;
                let angle = idx as f32 * angle_step;
                let offset = Vec2f {
                    x: angle.cos() * 100.0,
                    y: angle.sin() * 100.0,
                };
                let Some(slot_idx) = runtime_alloc_creature_slot(state) else {
                    continue;
                };
                let stale_target_heading = state.creatures[slot_idx].target_heading;
                let stale_heading = state.creatures[slot_idx].heading;
                let heading = if idx == 7 {
                    f64::from(final_heading)
                } else {
                    stale_heading
                };
                state.creatures[slot_idx] = RuntimeCreature {
                    active: true,
                    pos: call.pos,
                    vel: Vec2f { x: 0.0, y: 0.0 },
                    // Native child init preserves stale heading when template
                    // child heading is unset.
                    heading,
                    target: call.pos,
                    target_heading: stale_target_heading,
                    force_target: 0,
                    target_offset: offset,
                    orbit_angle: 0.0,
                    orbit_radius: 0.0,
                    phase_seed: child_phase_seed,
                    move_scale: 1.0,
                    type_id: CREATURE_TYPE_ALIEN,
                    flags: 0,
                    ai_mode: CREATURE_AI_MODE_FOLLOW_LINK,
                    // Ring children link to the parent creature.
                    link_index: parent_idx,
                    health: 40.0,
                    max_health: 40.0,
                    move_speed: 2.4,
                    reward_value: 60.0,
                    size: 50.0,
                    contact_damage: 4.0,
                    attack_cooldown: 0.0,
                    lifecycle_stage: CREATURE_LIFECYCLE_ALIVE,
                    tint: [0.32, 0.588, 0.426, 1.0],
                };
            }
        }
        SPAWN_ID_ALIEN_CONST_RED_FAST_2B => {
            runtime_spawn_template_creature(
                state,
                call.pos,
                call.heading,
                CREATURE_TYPE_ALIEN,
                0,
                CREATURE_AI_MODE_ORBIT_PLAYER,
                30.0,
                3.6,
                450.0,
                35.0,
                20.0,
                [1.0, 0.3, 0.3, 1.0],
            );
        }
        SPAWN_ID_ALIEN_CONST_RED_BOSS_2C => {
            runtime_spawn_template_creature(
                state,
                call.pos,
                call.heading,
                CREATURE_TYPE_ALIEN,
                0,
                CREATURE_AI_MODE_ORBIT_PLAYER,
                3800.0,
                2.0,
                1500.0,
                80.0,
                40.0,
                [0.85, 0.2, 0.2, 1.0],
            );
        }
        SPAWN_ID_SPIDER_SP2_RANDOM_35 => {
            runtime_spawn_template_creature(
                state,
                call.pos,
                call.heading,
                CREATURE_TYPE_SPIDER_SP2,
                0,
                CREATURE_AI_MODE_ORBIT_PLAYER,
                59.0,
                1.95,
                118.0,
                34.0,
                8.5,
                [0.8, 0.9, 0.8, 1.0],
            );
        }
        SPAWN_ID_SPIDER_SP1_AI7_TIMER_38 => {
            let spawned_idx = runtime_spawn_template_creature(
                state,
                call.pos,
                call.heading,
                CREATURE_TYPE_SPIDER_SP1,
                CREATURE_FLAG_AI7_LINK_TIMER,
                CREATURE_AI_MODE_ORBIT_PLAYER,
                50.0,
                4.8,
                433.0,
                42.0,
                10.0,
                [1.0, 0.75, 0.1, 1.0],
            );
            if let Ok(idx) = usize::try_from(spawned_idx) {
                state.creatures[idx].link_index = 0;
            }
        }
        SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A => {
            runtime_spawn_template_creature(
                state,
                call.pos,
                call.heading,
                CREATURE_TYPE_SPIDER_SP1,
                0,
                CREATURE_AI_MODE_ORBIT_PLAYER,
                4500.0,
                2.0,
                4500.0,
                64.0,
                50.0,
                [1.0, 1.0, 1.0, 1.0],
            );
        }
        SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C => {
            runtime_spawn_template_creature(
                state,
                call.pos,
                call.heading,
                CREATURE_TYPE_SPIDER_SP1,
                0,
                CREATURE_AI_MODE_ORBIT_PLAYER,
                200.0,
                2.0,
                200.0,
                40.0,
                20.0,
                [0.9, 0.1, 0.1, 1.0],
            );
        }
        _ => {}
    }
}

fn consume_survival_template_build_rng(rng: &mut CrtRand, template_id: i32, heading: f32) {
    let _phase_seed = rng.rand() & 0x17F;
    if heading == RANDOM_HEADING_SENTINEL {
        let _ = rng.rand() % 628;
    }
    let _ = rng.rand() % 314;

    match template_id {
        SPAWN_ID_FORMATION_RING_ALIEN_8_12 => {
            for _ in 0..8 {
                rng.rand();
            }
        }
        SPAWN_ID_SPIDER_SP2_RANDOM_35 => {
            for _ in 0..4 {
                rng.rand();
            }
        }
        SPAWN_ID_SPIDER_SP1_AI7_TIMER_38 => {
            rng.rand();
        }
        SPAWN_ID_ALIEN_CONST_RED_BOSS_2C
        | SPAWN_ID_ALIEN_CONST_RED_FAST_2B
        | SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A
        | SPAWN_ID_SPIDER_SP2_SPLITTER_01
        | SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C => {}
        _ => {}
    }
}

fn consume_spawn_burst_rng(rng: &mut CrtRand, count: usize) {
    for _ in 0..count {
        rng.rand();
        rng.rand();
        rng.rand();
        rng.rand();
    }
}

fn consume_fx_queue_add_random_rng(rng: &mut CrtRand) {
    let _ = rng.rand();
    let _ = rng.rand();
    let _ = rng.rand();
    let _ = rng.rand();
}

fn consume_spawn_blood_splatter_rng(rng: &mut CrtRand) {
    for _ in 0..2 {
        let _ = rng.rand();
        let _ = rng.rand();
        let _ = rng.rand();
        let _ = rng.rand();
        let _ = rng.rand();
    }
}

fn consume_projectile_hit_pre_rng(state: &mut SimState) {
    let freeze_active = state.bonuses.freeze > 0.0;
    let bloody = perk_active(&state.player, PERK_BLOODY_MESS_QUICK_LEARNER);
    if freeze_active && !bloody {
        return;
    }
    let rng = &mut state.rng;
    for _ in 0..2 {
        consume_spawn_blood_splatter_rng(rng);
        if (rng.rand() & 7) == 2 {
            consume_spawn_blood_splatter_rng(rng);
        }
    }
}

fn consume_projectile_hit_post_rng(rng: &mut CrtRand, type_id: i64, freeze_active: bool) {
    let _ = rng.rand();
    if type_id == PROJECTILE_TYPE_GAUSS_GUN || type_id == PROJECTILE_TYPE_FIRE_BULLETS {
        // Hooked path (`queue_large_hit_decal_streak`) for Gauss/Fire Bullets.
        for _ in 0..6 {
            let mut dist = (rng.rand() % 100) as f32 * 0.1;
            if dist > 4.0 {
                dist = (rng.rand() % 0x5A + 10) as f32 * 0.1;
            }
            if dist > 7.0 {
                let _ = rng.rand();
            }
            // Native consumes one unconditional draw per loop before freeze branch.
            let _ = rng.rand();
            if freeze_active {
                let _ = rng.rand();
                consume_spawn_freeze_shard_rng(rng);
            }
            consume_fx_queue_add_random_rng(rng);
        }
        return;
    }
    if freeze_active {
        // Non-Gauss/non-Fire freeze hits spawn one extra shard in projectile
        // update: angle draw + `effect_spawn_freeze_shard` payload draws.
        let _ = rng.rand();
        consume_spawn_freeze_shard_rng(rng);
        return;
    }
    for _ in 0..3 {
        let _ = rng.rand();
        consume_fx_queue_add_random_rng(rng);
        consume_fx_queue_add_random_rng(rng);
        consume_fx_queue_add_random_rng(rng);
        consume_fx_queue_add_random_rng(rng);
    }
}

fn consume_spawn_freeze_shard_rng(rng: &mut CrtRand) {
    let _ = rng.rand();
    let _ = rng.rand();
    let _ = rng.rand();
    let _ = rng.rand();
    let _ = rng.rand();
    let _ = rng.rand();
}

fn consume_spawn_freeze_shatter_rng(rng: &mut CrtRand) {
    for _ in 0..4 {
        let _ = rng.rand();
        let _ = rng.rand();
    }
    for _ in 0..4 {
        let _ = rng.rand();
        consume_spawn_freeze_shard_rng(rng);
    }
}

fn consume_bonus_freeze_corpse_shatter_rng(rng: &mut CrtRand) {
    for _ in 0..8 {
        let _ = rng.rand();
        consume_spawn_freeze_shard_rng(rng);
    }
    let _ = rng.rand();
    consume_spawn_freeze_shatter_rng(rng);
}

fn projectile_hit_sfx_uses_random_variant(type_id: i64) -> bool {
    !matches!(
        type_id,
        PROJECTILE_TYPE_ION_RIFLE | PROJECTILE_TYPE_ION_MINIGUN | PROJECTILE_TYPE_ION_CANNON
    )
}

fn consume_projectile_ion_hit_effect_rng(state: &mut SimState, type_id: i64) {
    let mut count = match type_id {
        PROJECTILE_TYPE_ION_MINIGUN => 3,
        PROJECTILE_TYPE_ION_RIFLE => 4,
        PROJECTILE_TYPE_ION_CANNON => 8,
        _ => return,
    };
    if state.detail_preset < 3 {
        count /= 2;
    }
    for _ in 0..count {
        let _ = state.rng.rand();
        let _ = state.rng.rand();
        let _ = state.rng.rand();
        let _ = state.rng.rand();
    }
}

fn consume_projectile_hit_sfx_rng(state: &mut SimState, type_id: i64) {
    if !state.demo_mode_active && state.game_mode != GAME_MODE_RUSH && !state.game_tune_started {
        state.game_tune_started = true;
        return;
    }
    if !projectile_hit_sfx_uses_random_variant(type_id) {
        return;
    }
    let _ = state.rng.rand();
    state.debug_hit_sfx_draws_tick = state.debug_hit_sfx_draws_tick.saturating_add(1);
}

fn alloc_survival_spawn_creature(pos: Vec2f, rng: &mut CrtRand) -> SurvivalSpawnCreature {
    let phase_seed = (rng.rand() & 0x17F) as f32;
    SurvivalSpawnCreature {
        pos,
        heading: 0.0,
        phase_seed,
        target: pos,
        target_heading: 0.0,
        force_target: 0,
        target_offset: Vec2f { x: 0.0, y: 0.0 },
        orbit_angle: 0.0,
        orbit_radius: 0.0,
        move_scale: 1.0,
        type_id: -1,
        flags: 0,
        ai_mode: CREATURE_AI_MODE_ORBIT_PLAYER,
        link_index: -1,
        health: 0.0,
        max_health: 0.0,
        move_speed: 0.0,
        reward_value: 0.0,
        size: 0.0,
        contact_damage: 0.0,
        lifecycle_stage: CREATURE_LIFECYCLE_ALIVE,
        tint: [1.0, 1.0, 1.0, 1.0],
    }
}

fn clamp01(value: f32) -> f32 {
    if value < 0.0 {
        return 0.0;
    }
    if 1.0 < value {
        return 1.0;
    }
    value
}

fn replay_input_aim_or_default(input: &PackedPlayerInput, fallback: Vec2f) -> Vec2f {
    let aim_x = input.aim_x as f32;
    let aim_y = input.aim_y as f32;
    if !aim_x.is_finite() || !aim_y.is_finite() {
        return fallback.add(Vec2f { x: 1.0, y: 0.0 });
    }
    let aim = Vec2f { x: aim_x, y: aim_y };
    if aim.sub(fallback).length_sq() <= f32::EPSILON {
        return fallback.add(Vec2f { x: 1.0, y: 0.0 });
    }
    aim
}

fn replay_input_move_or_zero(input: &PackedPlayerInput) -> Vec2f {
    let move_x = input.move_x as f32;
    let move_y = input.move_y as f32;
    if !move_x.is_finite() || !move_y.is_finite() {
        return Vec2f { x: 0.0, y: 0.0 };
    }
    Vec2f {
        x: move_x,
        y: move_y,
    }
}

fn normalize_heading_angle(mut value: f32) -> f32 {
    value = value as f32;
    while value < 0.0 {
        value = (value + NATIVE_TAU) as f32;
    }
    while value > NATIVE_TAU {
        value = (value - NATIVE_TAU) as f32;
    }
    value
}

fn direction_from_heading_native(heading: f32) -> Vec2f {
    let radians = f64::from(heading as f32) - f64::from(NATIVE_HALF_PI);
    Vec2f {
        x: radians.cos() as f32,
        y: radians.sin() as f32,
    }
}

fn direction_from_heading_native_f64(heading: f32) -> (f64, f64) {
    let radians = f64::from(heading) - f64::from(NATIVE_HALF_PI);
    (radians.cos(), radians.sin())
}

fn heading_from_direction_native(direction: Vec2f) -> f32 {
    let dx = f64::from(direction.x as f32);
    let dy = f64::from(direction.y as f32);
    let mut heading = (dy.atan2(dx) + f64::from(NATIVE_HALF_PI)) as f32;
    let left_axis_heading_pos = (NATIVE_TAU - NATIVE_HALF_PI) as f32;
    if dx < 0.0 && (heading - left_axis_heading_pos).abs() <= 1.0e-6 && dy.abs() <= 5.0e-4 {
        heading = (heading - NATIVE_TAU) as f32;
    }
    heading
}

fn resolve_move_mode_for_update(input_flags: ReplayInputFlags, demo_mode_active: bool) -> i64 {
    if let Some(mode) = input_flags.move_mode {
        return mode;
    }
    if demo_mode_active {
        return MOVEMENT_CONTROL_TYPE_COMPUTER;
    }
    if input_flags.move_forward_pressed.is_some()
        && input_flags.move_backward_pressed.is_some()
        && input_flags.turn_left_pressed.is_some()
        && input_flags.turn_right_pressed.is_some()
    {
        return MOVEMENT_CONTROL_TYPE_STATIC;
    }
    MOVEMENT_CONTROL_TYPE_DUAL_ACTION_PAD
}

fn resolve_aim_scheme_for_update(input_flags: ReplayInputFlags, demo_mode_active: bool) -> i64 {
    if let Some(aim_scheme) = input_flags.aim_scheme {
        return aim_scheme;
    }
    if demo_mode_active {
        return AIM_SCHEME_COMPUTER;
    }
    AIM_SCHEME_MOUSE
}

fn player_heading_approach_target_with_delta(
    player: &mut PlayerState,
    target_heading: f32,
    dt: f32,
) -> (f32, f32) {
    let heading = normalize_heading_angle(player.heading as f32);
    player.heading = heading;
    let target = target_heading as f32;

    let direct = ((target - heading) as f32).abs() as f32;
    let mut high = heading;
    if target > high {
        high = target;
    }
    let mut low = heading;
    if target < low {
        low = target;
    }
    let wrapped = ((NATIVE_TAU - high + low) as f32).abs() as f32;
    let diff = if direct >= wrapped { wrapped } else { direct };

    let dt_f32 = dt as f32;
    let scaled = (dt_f32 * diff) as f32;
    let turn_delta = if direct <= wrapped {
        if target > heading {
            (scaled * 5.0) as f32
        } else {
            (scaled * -5.0) as f32
        }
    } else if target >= heading {
        (scaled * -5.0) as f32
    } else {
        (scaled * 5.0) as f32
    };

    player.heading = (heading + turn_delta) as f32;
    (diff, turn_delta)
}

fn player_heading_approach_target(player: &mut PlayerState, target_heading: f32, dt: f32) -> f32 {
    let (diff, _) = player_heading_approach_target_with_delta(player, target_heading, dt);
    diff
}

fn player_accelerate_move_speed(player: &mut PlayerState, dt: f32) {
    let dt_f32 = dt as f32;
    if perk_active(player, PERK_LONG_DISTANCE_RUNNER) {
        if player.move_speed < 2.0 {
            player.move_speed = (player.move_speed + dt_f32 * 4.0) as f32;
        }
        player.move_speed = (player.move_speed + dt_f32) as f32;
        if player.move_speed > 2.8 {
            player.move_speed = 2.8;
        }
    } else {
        player.move_speed = (player.move_speed + dt_f32 * 5.0) as f32;
        if player.move_speed > 2.0 {
            player.move_speed = 2.0;
        }
    }
}

fn player_decelerate_move_speed(player: &mut PlayerState, dt: f32) {
    let dt_f32 = dt as f32;
    player.move_speed = (player.move_speed - dt_f32 * 15.0) as f32;
    if player.move_speed < 0.0 {
        player.move_speed = 0.0;
    }
}

fn player_apply_move_speed_caps(player: &mut PlayerState) {
    if player.weapon_id == WEAPON_MEAN_MINIGUN && player.move_speed > 0.8 {
        player.move_speed = 0.8;
    }
}

fn player_move_delta_from_heading(
    player: &PlayerState,
    movement_dt: f32,
    speed_scale: f32,
) -> Vec2f {
    let (move_dir_x, move_dir_y) = direction_from_heading_native_f64(player.heading);
    let move_dx = (move_dir_x * f64::from(player.move_speed) * f64::from(speed_scale)) as f32;
    let move_dy = (move_dir_y * f64::from(player.move_speed) * f64::from(speed_scale)) as f32;
    Vec2f {
        x: (f64::from(movement_dt) * f64::from(move_dx)) as f32,
        y: (f64::from(movement_dt) * f64::from(move_dy)) as f32,
    }
}

fn player_aim_point_from_heading(player_pos: Vec2f, heading: f32, radius: f32) -> Vec2f {
    let (aim_dir_x, aim_dir_y) = direction_from_heading_native_f64(heading);
    Vec2f {
        x: (f64::from(player_pos.x) + aim_dir_x * f64::from(radius)) as f32,
        y: (f64::from(player_pos.y) + aim_dir_y * f64::from(radius)) as f32,
    }
}

fn player_update_aim_by_scheme(
    state: &mut SimState,
    input_aim: Vec2f,
    dt: f32,
    movement_mode: i64,
    aim_scheme: i64,
    input_flags: ReplayInputFlags,
) {
    let mut target_aim = input_aim;
    if !state.demo_mode_active && aim_scheme != AIM_SCHEME_COMPUTER {
        if aim_scheme == AIM_SCHEME_KEYBOARD {
            if movement_mode == MOVEMENT_CONTROL_TYPE_RELATIVE
                || movement_mode == MOVEMENT_CONTROL_TYPE_STATIC
            {
                if input_flags.turn_right_pressed.unwrap_or(false) {
                    state.player.aim_heading = (state.player.aim_heading
                        + (dt as f32 * AIM_KEYBOARD_TURN_RATE) as f32)
                        as f32;
                }
                if input_flags.turn_left_pressed.unwrap_or(false) {
                    state.player.aim_heading = (state.player.aim_heading
                        - (dt as f32 * AIM_KEYBOARD_TURN_RATE) as f32)
                        as f32;
                }
                target_aim = player_aim_point_from_heading(
                    state.player_pos,
                    state.player.aim_heading,
                    AIM_POINT_RADIUS,
                );
            }
        } else if aim_scheme == AIM_SCHEME_JOYSTICK {
            if input_flags.turn_right_pressed.unwrap_or(false) {
                state.player.aim_heading =
                    (state.player.aim_heading + (dt as f32 * AIM_JOYSTICK_TURN_RATE) as f32) as f32;
            }
            if input_flags.turn_left_pressed.unwrap_or(false) {
                state.player.aim_heading =
                    (state.player.aim_heading - (dt as f32 * AIM_JOYSTICK_TURN_RATE) as f32) as f32;
            }
            target_aim = player_aim_point_from_heading(
                state.player_pos,
                state.player.aim_heading,
                AIM_POINT_RADIUS,
            );
        } else if aim_scheme == AIM_SCHEME_UNKNOWN {
            target_aim = player_aim_point_from_heading(
                state.player_pos,
                state.player.aim_heading,
                AIM_POINT_RADIUS,
            );
        }
    }

    state.player.aim = target_aim;
    let aim_delta = target_aim.sub(state.player_pos);
    let aim_dir = aim_delta.normalized_or_zero();
    if aim_dir.length_sq() > 0.0 {
        state.player.aim_heading = heading_from_direction_native(aim_dir);
    }
}

fn player_update_position(
    state: &mut SimState,
    move_input: Vec2f,
    dt_s: f32,
    move_mode: i64,
    aim_scheme: i64,
    input_flags: ReplayInputFlags,
) {
    if dt_s <= 0.0 {
        return;
    }
    let debug_tick = std::env::var("CRIMSON_RUST_DEBUG_TICK")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());

    let terrain_width = state.survival_terrain_width as f32;
    let terrain_height = state.survival_terrain_height as f32;
    let mut next_pos = state.player_pos;
    let before_pos = state.player_pos;
    let mut debug_move_speed_before = 0.0_f32;
    let mut debug_move_speed_after = 0.0_f32;
    let mut debug_speed_multiplier = 0.0_f32;
    let mut debug_speed = 0.0_f32;
    let mut debug_move_delta = Vec2f { x: 0.0, y: 0.0 };
    let mut debug_target_heading: Option<f32> = None;
    let mut debug_angle_diff: Option<f32> = None;
    let mut phase_sign = 1.0_f32;
    {
        let player = &mut state.player;
        debug_move_speed_before = player.move_speed;
        let raw_mag = (f64::from(move_input.x) * f64::from(move_input.x)
            + f64::from(move_input.y) * f64::from(move_input.y))
        .sqrt() as f32;
        let mut move_dir = direction_from_heading_native_f64(player.heading);
        let mut speed_multiplier = player.speed_multiplier as f32;
        if player.speed_bonus_timer > 0.0 {
            speed_multiplier += 1.0;
        }
        debug_speed_multiplier = speed_multiplier;

        let mut movement_dt = dt_s as f32;
        if state.time_scale_active && movement_dt > 0.0 {
            let reflex_f32 = state.bonuses.reflex_boost as f32;
            let mut time_scale_factor = 0.3_f32;
            if reflex_f32 < 1.0 {
                // Python computes in f64 from f32 inputs, then stores to f32.
                time_scale_factor = ((1.0_f64 - f64::from(reflex_f32)) * 0.7_f64 + 0.3_f64) as f32;
            }
            if time_scale_factor > 0.0 {
                // Python parity: divide/multiply in f64 from f32 inputs, then store once to f32.
                movement_dt =
                    ((0.6_f64 / f64::from(time_scale_factor)) * f64::from(movement_dt)) as f32;
            }
            if debug_tick == Some(state.debug_tick_index) {
                eprintln!(
                    "dbg time_scale tick={} dt_s={} dt_s_bits={:#010x} reflex={} reflex_bits={:#010x} time_scale_factor={} ts_bits={:#010x} movement_dt={} movement_dt_bits={:#010x}",
                    state.debug_tick_index,
                    dt_s,
                    dt_s.to_bits(),
                    reflex_f32,
                    reflex_f32.to_bits(),
                    time_scale_factor,
                    time_scale_factor.to_bits(),
                    movement_dt,
                    movement_dt.to_bits()
                );
            }
        }
        let player_controlled_movement = !state.demo_mode_active
            && move_mode != MOVEMENT_CONTROL_TYPE_COMPUTER
            && aim_scheme != AIM_SCHEME_COMPUTER;
        let mut speed = 0.0_f32;
        let mut move_delta_override: Option<Vec2f> = None;
        if player_controlled_movement {
            if move_mode == MOVEMENT_CONTROL_TYPE_RELATIVE {
                let turning_left = input_flags.turn_left_pressed.unwrap_or(false);
                let turning_right = input_flags.turn_right_pressed.unwrap_or(false);
                let moving_forward = input_flags.move_forward_pressed.unwrap_or(false);
                let moving_backward = input_flags.move_backward_pressed.unwrap_or(false);
                let mut turned = false;

                if player.turn_speed < 1.0 {
                    player.turn_speed = 1.0;
                }
                if player.turn_speed > 7.0 {
                    player.turn_speed = 7.0;
                }

                if turning_left {
                    player.turn_speed = (player.turn_speed + movement_dt * 10.0) as f32;
                    let turn_step = (player.turn_speed * movement_dt * 0.5) as f32;
                    player.heading = (player.heading - turn_step) as f32;
                    player.aim_heading = (player.aim_heading - turn_step) as f32;
                    turned = true;
                } else if turning_right {
                    player.turn_speed = (player.turn_speed + movement_dt * 10.0) as f32;
                    let turn_step = (player.turn_speed * movement_dt * 0.5) as f32;
                    player.heading = (player.heading + turn_step) as f32;
                    player.aim_heading = (player.aim_heading + turn_step) as f32;
                    turned = true;
                }

                if moving_forward {
                    player_accelerate_move_speed(player, movement_dt);
                    player_apply_move_speed_caps(player);
                    move_delta_override =
                        Some(player_move_delta_from_heading(player, movement_dt, 25.0));
                } else if moving_backward {
                    player_accelerate_move_speed(player, movement_dt);
                    phase_sign = -1.0;
                    move_delta_override =
                        Some(player_move_delta_from_heading(player, movement_dt, -25.0));
                } else {
                    if !turned {
                        player.turn_speed = 1.0;
                    }
                    player_decelerate_move_speed(player, movement_dt);
                    move_delta_override =
                        Some(player_move_delta_from_heading(player, movement_dt, 25.0));
                }
            } else if move_mode == MOVEMENT_CONTROL_TYPE_STATIC {
                let moving_forward = input_flags
                    .move_forward_pressed
                    .unwrap_or(move_input.y < -0.5);
                let moving_backward = input_flags
                    .move_backward_pressed
                    .unwrap_or(move_input.y > 0.5);
                let turning_left = input_flags.turn_left_pressed.unwrap_or(move_input.x < -0.5);
                let turning_right = input_flags.turn_right_pressed.unwrap_or(move_input.x > 0.5);

                let mut target_heading = RELATIVE_MOVE_HEADING_NONE;
                if turning_left {
                    target_heading = RELATIVE_MOVE_HEADING_LEFT;
                }
                if turning_right {
                    target_heading = RELATIVE_MOVE_HEADING_RIGHT;
                }
                if moving_forward {
                    if turning_left {
                        target_heading = RELATIVE_MOVE_HEADING_FORWARD_LEFT;
                    } else if turning_right {
                        target_heading = RELATIVE_MOVE_HEADING_FORWARD_RIGHT;
                    } else {
                        target_heading = RELATIVE_MOVE_HEADING_FORWARD;
                    }
                }
                if moving_backward {
                    if turning_left {
                        target_heading = RELATIVE_MOVE_HEADING_BACKWARD_LEFT;
                    } else if turning_right {
                        target_heading = RELATIVE_MOVE_HEADING_BACKWARD_RIGHT;
                    } else {
                        target_heading = RELATIVE_MOVE_HEADING_BACKWARD;
                    }
                }

                let move_dx: f32;
                let move_dy: f32;
                if !moving_backward && target_heading == RELATIVE_MOVE_HEADING_NONE {
                    player_decelerate_move_speed(player, movement_dt);
                    move_dir = direction_from_heading_native_f64(player.heading);
                    move_dx = (move_dir.0
                        * f64::from(player.move_speed)
                        * f64::from(speed_multiplier)
                        * 25.0) as f32;
                    move_dy = (move_dir.1
                        * f64::from(player.move_speed)
                        * f64::from(speed_multiplier)
                        * 25.0) as f32;
                } else {
                    let (angle_diff, turn_delta) = player_heading_approach_target_with_delta(
                        player,
                        target_heading,
                        movement_dt,
                    );
                    debug_target_heading = Some(target_heading);
                    debug_angle_diff = Some(angle_diff);
                    player.aim_heading = (player.aim_heading + turn_delta) as f32;
                    player_accelerate_move_speed(player, movement_dt);
                    player_apply_move_speed_caps(player);
                    move_dir = direction_from_heading_native_f64(player.heading);
                    let turn_align = ((f64::from(NATIVE_PI) - f64::from(angle_diff))
                        * f64::from(speed_multiplier)
                        * f64::from(RELATIVE_MOVE_TURN_ALIGN_SCALE));
                    move_dx = (move_dir.0 * f64::from(player.move_speed) * turn_align) as f32;
                    move_dy = (move_dir.1 * f64::from(player.move_speed) * turn_align) as f32;
                    if debug_tick == Some(state.debug_tick_index) {
                        eprintln!(
                            "dbg static_calc tick={} movement_dt={} angle_diff={} turn_delta={} move_dir=({}, {}) turn_align={} move_dx={} move_dy={}",
                            state.debug_tick_index,
                            movement_dt,
                            angle_diff,
                            turn_delta,
                            move_dir.0,
                            move_dir.1,
                            turn_align,
                            move_dx,
                            move_dy
                        );
                    }
                }
                move_delta_override = Some(Vec2f {
                    x: (f64::from(movement_dt) * f64::from(move_dx)) as f32,
                    y: (f64::from(movement_dt) * f64::from(move_dy)) as f32,
                });
            } else {
                let moving_input = raw_mag
                    > if move_mode == MOVEMENT_CONTROL_TYPE_MOUSE_POINT_CLICK {
                        0.0
                    } else {
                        0.2
                    };
                let mut turn_alignment_scale = 1.0_f32;
                if moving_input {
                    let inv = if raw_mag > 1e-9 { 1.0 / raw_mag } else { 0.0 };
                    move_dir = (
                        f64::from(move_input.x) * f64::from(inv),
                        f64::from(move_input.y) * f64::from(inv),
                    );
                    let target_heading = normalize_heading_angle(
                        (move_dir.1.atan2(move_dir.0) + std::f64::consts::FRAC_PI_2) as f32,
                    );
                    let angle_diff =
                        player_heading_approach_target(player, target_heading, movement_dt);
                    debug_target_heading = Some(target_heading);
                    debug_angle_diff = Some(angle_diff);
                    move_dir = direction_from_heading_native_f64(player.heading);
                    turn_alignment_scale = ((std::f64::consts::PI - f64::from(angle_diff))
                        / std::f64::consts::PI)
                        .max(0.0) as f32;
                    player_accelerate_move_speed(player, movement_dt);
                } else {
                    player_decelerate_move_speed(player, movement_dt);
                    move_dir = direction_from_heading_native_f64(player.heading);
                }
                player_apply_move_speed_caps(player);
                speed = (player.move_speed * speed_multiplier * 25.0) as f32;
                if moving_input {
                    speed = (speed * raw_mag.min(1.0)) as f32;
                    speed = (speed * turn_alignment_scale) as f32;
                }
            }
        } else {
            let moving_input = raw_mag > if state.demo_mode_active { 0.0 } else { 0.2 };
            let mut turn_alignment_scale = 1.0_f32;
            if moving_input {
                let inv = if raw_mag > 1e-9 { 1.0 / raw_mag } else { 0.0 };
                move_dir = (
                    f64::from(move_input.x) * f64::from(inv),
                    f64::from(move_input.y) * f64::from(inv),
                );
                let target_heading = normalize_heading_angle(
                    (move_dir.1.atan2(move_dir.0) + std::f64::consts::FRAC_PI_2) as f32,
                );
                let angle_diff =
                    player_heading_approach_target(player, target_heading, movement_dt);
                debug_target_heading = Some(target_heading);
                debug_angle_diff = Some(angle_diff);
                move_dir = direction_from_heading_native_f64(player.heading);
                turn_alignment_scale = ((std::f64::consts::PI - f64::from(angle_diff))
                    / std::f64::consts::PI)
                    .max(0.0) as f32;
                player_accelerate_move_speed(player, movement_dt);
            } else {
                player_decelerate_move_speed(player, movement_dt);
                move_dir = direction_from_heading_native_f64(player.heading);
            }
            player_apply_move_speed_caps(player);
            speed = (player.move_speed * speed_multiplier * 25.0) as f32;
            if moving_input {
                speed = (speed * raw_mag.min(1.0)) as f32;
                speed = (speed * turn_alignment_scale) as f32;
            }
        }

        let move_delta = if let Some(delta) = move_delta_override {
            delta
        } else {
            let move_step = (speed * movement_dt) as f32;
            Vec2f {
                x: (move_dir.0 * f64::from(move_step)) as f32,
                y: (move_dir.1 * f64::from(move_step)) as f32,
            }
        };
        debug_move_speed_after = player.move_speed;
        debug_speed = speed;
        debug_move_delta = move_delta;
        next_pos = next_pos.add(move_delta);

        player.move_phase += phase_sign * movement_dt * player.move_speed * 19.0;
        while player.move_phase > 14.0 {
            player.move_phase -= 14.0;
        }
        while player.move_phase < 0.0 {
            player.move_phase += 14.0;
        }
    }

    let half_size = (state.player.size * 0.5).max(0.0);
    let min_x = half_size;
    let min_y = half_size;
    let max_x = (terrain_width - half_size).max(min_x);
    let max_y = (terrain_height - half_size).max(min_y);
    state.player_pos = Vec2f {
        x: next_pos.x.clamp(min_x, max_x),
        y: next_pos.y.clamp(min_y, max_y),
    };
    if debug_tick == Some(state.debug_tick_index) {
        eprintln!(
            "dbg move tick={} mode={} aim_scheme={} input=({}, {}) dt={} before=({:.9}, {:.9}) before_bits=({:#010x}, {:#010x}) move_speed_before={:.9} move_speed_after={:.9} speed_multiplier={:.9} target_heading={:?} angle_diff={:?} speed={:.9} move_delta=({:.9}, {:.9}) move_delta_bits=({:#010x}, {:#010x}) unclamped=({:.9}, {:.9}) unclamped_bits=({:#010x}, {:#010x}) after=({:.9}, {:.9}) after_bits=({:#010x}, {:#010x})",
            state.debug_tick_index,
            move_mode,
            aim_scheme,
            move_input.x,
            move_input.y,
            dt_s,
            before_pos.x,
            before_pos.y,
            before_pos.x.to_bits(),
            before_pos.y.to_bits(),
            debug_move_speed_before,
            debug_move_speed_after,
            debug_speed_multiplier,
            debug_target_heading,
            debug_angle_diff,
            debug_speed,
            debug_move_delta.x,
            debug_move_delta.y,
            debug_move_delta.x.to_bits(),
            debug_move_delta.y.to_bits(),
            next_pos.x,
            next_pos.y,
            next_pos.x.to_bits(),
            next_pos.y.to_bits(),
            state.player_pos.x,
            state.player_pos.y,
            state.player_pos.x.to_bits(),
            state.player_pos.y.to_bits(),
        );
    }
}

fn tick_player_bonus_timers(player: &mut PlayerState, dt: f32) {
    if dt <= 0.0 {
        return;
    }
    if player.shield_timer <= 0.0 {
        player.shield_timer = 0.0;
    } else {
        player.shield_timer -= dt;
    }

    if player.fire_bullets_timer <= 0.0 {
        player.fire_bullets_timer = 0.0;
    } else {
        player.fire_bullets_timer -= dt;
    }

    if player.speed_bonus_timer <= 0.0 {
        player.speed_bonus_timer = 0.0;
    } else {
        player.speed_bonus_timer -= dt;
    }
}

fn time_scale_reflex_boost_bonus(reflex_boost_timer: f32, time_scale_active: bool, dt: f32) -> f32 {
    let dt_f32 = dt as f32;
    if dt_f32 <= 0.0 {
        return dt_f32;
    }
    if !time_scale_active {
        return dt_f32;
    }
    let reflex_f32 = reflex_boost_timer as f32;
    let mut time_scale_factor = 0.3_f32;
    if reflex_f32 < 1.0 {
        time_scale_factor = ((1.0_f64 - f64::from(reflex_f32)) * 0.7_f64 + 0.3_f64) as f32;
    }
    (f64::from(dt_f32) * f64::from(time_scale_factor)) as f32
}

fn apply_reflex_boosted_dt(dt: f32, player: &PlayerState) -> f32 {
    if dt <= 0.0 {
        return dt;
    }
    if !perk_active(player, PERK_REFLEX_BOOSTED) {
        return dt;
    }
    dt * 0.9
}

fn player_frame_dt_after_roundtrip(
    dt: f32,
    time_scale_active: bool,
    reflex_boost_timer: f32,
) -> f32 {
    let dt_f32 = dt as f32;
    if !time_scale_active || dt_f32 <= 0.0 {
        return dt_f32;
    }
    let reflex_f32 = reflex_boost_timer as f32;
    let mut time_scale_factor = 0.3_f32;
    if reflex_f32 < 1.0 {
        time_scale_factor = ((1.0_f64 - f64::from(reflex_f32)) * 0.7_f64 + 0.3_f64) as f32;
    }
    if time_scale_factor <= 0.0 {
        return dt_f32;
    }
    let movement_dt = ((0.6_f64 / f64::from(time_scale_factor)) * f64::from(dt_f32)) as f32;
    ((f64::from(time_scale_factor) * f64::from(movement_dt)) * 1.666_666_6_f64) as f32
}

fn bonus_entry_is_empty(entry: &BonusEntry) -> bool {
    entry.bonus_id == BONUS_ID_UNUSED
        && !entry.picked
        && entry.time_left <= 0.0
        && entry.time_max <= 0.0
        && entry.amount == 0
}

fn bonus_clear_entry(entry: &mut BonusEntry) {
    entry.bonus_id = BONUS_ID_UNUSED;
    entry.picked = false;
    entry.time_left = 0.0;
    entry.time_max = 0.0;
    entry.amount = 0;
}

fn bonus_default_amount(bonus_id: i32) -> i32 {
    match bonus_id {
        BONUS_ID_POINTS => 500,
        BONUS_ID_ENERGIZER => 8,
        BONUS_ID_WEAPON => 3,
        BONUS_ID_WEAPON_POWER_UP => 10,
        BONUS_ID_NUKE => 1,
        BONUS_ID_DOUBLE_EXPERIENCE => 1,
        BONUS_ID_SHOCK_CHAIN => 1,
        BONUS_ID_FIREBLAST => 1,
        BONUS_ID_REFLEX_BOOST => 3,
        BONUS_ID_SHIELD => 7,
        BONUS_ID_FREEZE => 5,
        BONUS_ID_MEDIKIT => 10,
        BONUS_ID_SPEED => 8,
        BONUS_ID_FIRE_BULLETS => 4,
        _ => 0,
    }
}

fn bonus_apply_seconds(bonus_id: i32, amount: i32) -> f32 {
    match bonus_id {
        BONUS_ID_DOUBLE_EXPERIENCE => 6.0,
        BONUS_ID_FIRE_BULLETS => 5.0,
        BONUS_ID_ENERGIZER => 8.0,
        _ => amount as f32,
    }
}

fn bonus_enabled(bonus_id: i32) -> bool {
    (BONUS_ID_POINTS..=BONUS_ID_FIRE_BULLETS).contains(&bonus_id)
}

fn bonus_id_from_roll(roll: i32, rng: &mut CrtRand) -> i32 {
    if !(1..=162).contains(&roll) {
        return BONUS_ID_UNUSED;
    }
    if roll <= 13 {
        return BONUS_ID_POINTS;
    }
    if roll == 14 {
        if (rng.rand() & 0x3F) == 0 {
            return BONUS_ID_ENERGIZER;
        }
        return BONUS_ID_WEAPON;
    }

    let mut v5 = roll - 14;
    let mut v6 = BONUS_ID_WEAPON;
    while v5 > 10 {
        v5 -= 10;
        v6 += 1;
        if v6 >= 15 {
            return BONUS_ID_UNUSED;
        }
    }
    v6
}

fn bonus_pick_random_type(state: &mut SimState) -> i32 {
    let has_fire_bullets_drop = state
        .bonus_pool
        .iter()
        .any(|entry| entry.bonus_id == BONUS_ID_FIRE_BULLETS && !entry.picked);

    for _ in 0..101 {
        let roll = i32::try_from(state.rng.rand() % 162 + 1).unwrap_or(1);
        let bonus_id = bonus_id_from_roll(roll, &mut state.rng);
        if bonus_id <= BONUS_ID_UNUSED {
            continue;
        }

        if state.shock_chain_links_left > 0 && bonus_id == BONUS_ID_SHOCK_CHAIN {
            continue;
        }
        if state.game_mode == GAME_MODE_QUESTS && state.quest_stage_minor == 10 {
            let major = state.quest_stage_major;
            if bonus_id == BONUS_ID_NUKE
                && (major == 2 || major == 4 || major == 5 || (state.hardcore && major == 3))
            {
                continue;
            }
            if bonus_id == BONUS_ID_FREEZE && (major == 4 || (state.hardcore && major == 2)) {
                continue;
            }
        }
        if bonus_id == BONUS_ID_FREEZE && state.bonuses.freeze > 0.0 {
            continue;
        }
        if bonus_id == BONUS_ID_SHIELD && state.player.shield_timer > 0.0 {
            continue;
        }
        if bonus_id == BONUS_ID_WEAPON && has_fire_bullets_drop {
            continue;
        }
        if bonus_id == BONUS_ID_WEAPON && perk_active(&state.player, PERK_MY_FAVOURITE_WEAPON) {
            continue;
        }
        if bonus_id == BONUS_ID_MEDIKIT && perk_active(&state.player, PERK_DEATH_CLOCK) {
            continue;
        }
        if !bonus_enabled(bonus_id) {
            continue;
        }

        return bonus_id;
    }

    BONUS_ID_POINTS
}

fn bonus_count_by_id(state: &SimState, bonus_id: i32) -> usize {
    state
        .bonus_pool
        .iter()
        .filter(|entry| entry.bonus_id == bonus_id)
        .count()
}

fn bonus_spawn_at_pos(state: &mut SimState, pos: Vec2f) -> Option<usize> {
    if pos.x < BONUS_SPAWN_MARGIN
        || pos.y < BONUS_SPAWN_MARGIN
        || pos.x > state.survival_terrain_width as f32 - BONUS_SPAWN_MARGIN
        || pos.y > state.survival_terrain_height as f32 - BONUS_SPAWN_MARGIN
    {
        return None;
    }

    let slot = state.bonus_pool.iter().position(bonus_entry_is_empty);
    let bonus_id = bonus_pick_random_type(state);

    let min_dist_sq = BONUS_SPAWN_MIN_DISTANCE * BONUS_SPAWN_MIN_DISTANCE;
    let blocked_spacing = state.bonus_pool.iter().any(|entry| {
        if entry.bonus_id == BONUS_ID_UNUSED {
            return false;
        }
        entry.pos.sub(pos).length_sq() < min_dist_sq
    });

    let amount = if bonus_id == BONUS_ID_WEAPON {
        i32::try_from(weapon_pick_random_available(state))
            .unwrap_or(i32::from(WEAPON_PISTOL as i16))
    } else if bonus_id == BONUS_ID_POINTS {
        if (state.rng.rand() & BONUS_POINTS_HIGH_CHANCE_MASK) < 3 {
            1000
        } else {
            500
        }
    } else {
        bonus_default_amount(bonus_id)
    };

    let Some(idx) = slot else {
        return None;
    };
    if blocked_spacing {
        return None;
    }

    let entry = &mut state.bonus_pool[idx];
    entry.bonus_id = bonus_id;
    entry.picked = false;
    entry.pos = pos;
    entry.time_left = BONUS_TIME_MAX;
    entry.time_max = BONUS_TIME_MAX;
    entry.amount = amount;
    Some(idx)
}

fn bonus_try_spawn_on_kill(state: &mut SimState, pos: Vec2f) -> bool {
    if state.game_mode == GAME_MODE_QUESTS {
        return false;
    }
    if state.demo_mode_active {
        return false;
    }
    if state.bonus_spawn_guard {
        return false;
    }

    if state.player.weapon_id == WEAPON_PISTOL && (state.rng.rand() & 3) < 3 {
        let spawned_idx = bonus_spawn_at_pos(state, pos);
        if let Some(idx) = spawned_idx {
            state.bonus_pool[idx].bonus_id = BONUS_ID_WEAPON;
        }

        let mut weapon_id = i32::try_from(weapon_pick_random_available(state)).unwrap_or(1);
        if weapon_id == WEAPON_PISTOL as i32 {
            weapon_id = i32::try_from(weapon_pick_random_available(state)).unwrap_or(1);
        }
        if let Some(idx) = spawned_idx {
            state.bonus_pool[idx].amount = weapon_id;
        }

        if bonus_count_by_id(state, BONUS_ID_WEAPON) > 1 {
            if let Some(idx) = spawned_idx {
                bonus_clear_entry(&mut state.bonus_pool[idx]);
            }
            return false;
        }
        if weapon_id == WEAPON_PISTOL as i32 || perk_active(&state.player, PERK_MY_FAVOURITE_WEAPON)
        {
            if let Some(idx) = spawned_idx {
                bonus_clear_entry(&mut state.bonus_pool[idx]);
            }
            return false;
        }
        return spawned_idx.is_some();
    }

    let base_roll = state.rng.rand();
    if base_roll % 9 != 1 {
        let mut allow_without_magnet = false;
        if state.player.weapon_id == WEAPON_PISTOL {
            allow_without_magnet = state.rng.rand() % 5 == 1;
        }
        if !allow_without_magnet {
            let has_bonus_magnet = perk_active(&state.player, PERK_BONUS_MAGNET);
            if !has_bonus_magnet {
                return false;
            }
            if state.rng.rand() % 10 != 2 {
                return false;
            }
        }
    }

    let Some(idx) = bonus_spawn_at_pos(state, pos) else {
        return false;
    };

    if state.bonus_pool[idx].bonus_id == BONUS_ID_WEAPON {
        let near_sq = BONUS_WEAPON_NEAR_RADIUS * BONUS_WEAPON_NEAR_RADIUS;
        if pos.sub(state.player_pos).length_sq() < near_sq {
            state.bonus_pool[idx].bonus_id = BONUS_ID_POINTS;
            state.bonus_pool[idx].amount = 100;
        }
    }

    if state.bonus_pool[idx].bonus_id != BONUS_ID_POINTS
        && bonus_count_by_id(state, state.bonus_pool[idx].bonus_id) > 1
    {
        bonus_clear_entry(&mut state.bonus_pool[idx]);
        return false;
    }

    if state.bonus_pool[idx].bonus_id == BONUS_ID_WEAPON {
        let amount = i64::from(state.bonus_pool[idx].amount);
        let carried_match =
            state.player.weapon_id == amount || state.player.alt_weapon_id == Some(amount);
        if carried_match {
            bonus_clear_entry(&mut state.bonus_pool[idx]);
            return false;
        }
    }

    true
}

fn bonus_apply(state: &mut SimState, bonus_id: i32, amount: i32, origin: Vec2f, dt: f32) {
    let economist_multiplier = if perk_active(&state.player, PERK_BONUS_ECONOMIST) {
        1.5
    } else {
        1.0
    };

    match bonus_id {
        BONUS_ID_POINTS => {
            if amount > 0 {
                state.player.experience = state.player.experience.saturating_add(i64::from(amount));
            }
        }
        BONUS_ID_ENERGIZER => {
            let add = bonus_apply_seconds(BONUS_ID_ENERGIZER, amount) * economist_multiplier;
            state.bonuses.energizer = (state.bonuses.energizer + add) as f32;
        }
        BONUS_ID_WEAPON => {
            let weapon_id = i64::from(amount);
            if perk_active(&state.player, PERK_ALTERNATE_WEAPON)
                && state.player.alt_weapon_id.is_none()
            {
                state.player.alt_weapon_id = Some(state.player.weapon_id);
            }
            weapon_assign_player(state, weapon_id);
        }
        BONUS_ID_WEAPON_POWER_UP => {
            let add = amount as f32 * economist_multiplier;
            state.bonuses.weapon_power_up = (state.bonuses.weapon_power_up + add) as f32;
            state.player.shot_cooldown = 0.0;
            state.player.reload_active = false;
            state.player.reload_timer = 0.0;
            state.player.reload_timer_max = 0.0;
            state.player.ammo = state.player.clip_size as f32;
        }
        BONUS_ID_DOUBLE_EXPERIENCE => {
            let add =
                bonus_apply_seconds(BONUS_ID_DOUBLE_EXPERIENCE, amount) * economist_multiplier;
            state.bonuses.double_experience = (state.bonuses.double_experience + add) as f32;
        }
        BONUS_ID_REFLEX_BOOST => {
            let add = amount as f32 * economist_multiplier;
            state.bonuses.reflex_boost = (state.bonuses.reflex_boost + add) as f32;
            state.player.ammo = state.player.clip_size as f32;
            state.player.reload_active = false;
            state.player.reload_timer = 0.0;
            state.player.reload_timer_max = 0.0;
        }
        BONUS_ID_SHIELD => {
            state.player.shield_timer =
                (state.player.shield_timer + amount as f32 * economist_multiplier) as f32;
        }
        BONUS_ID_FREEZE => {
            state.bonuses.freeze =
                (state.bonuses.freeze + amount as f32 * economist_multiplier) as f32;
            for idx in 0..state.creatures.len() {
                if !state.creatures[idx].active {
                    continue;
                }
                if state.creatures[idx].health > 0.0 {
                    continue;
                }
                if state.creatures[idx].lifecycle_stage < CREATURE_CORPSE_DESPAWN_LIFECYCLE {
                    state.creatures[idx].active = false;
                    continue;
                }
                let allow_shatter_fx = state
                    .freeze_corpse_indices_at_tick_start
                    .get(idx)
                    .copied()
                    .unwrap_or(true);
                if allow_shatter_fx {
                    consume_bonus_freeze_corpse_shatter_rng(&mut state.rng);
                }
                state.creatures[idx].active = false;
            }
        }
        BONUS_ID_MEDIKIT => {
            if state.player.health < 100.0 {
                state.player.health = (state.player.health + 10.0).min(100.0);
            }
        }
        BONUS_ID_SPEED => {
            state.player.speed_bonus_timer =
                (state.player.speed_bonus_timer + amount as f32 * economist_multiplier) as f32;
        }
        BONUS_ID_FIRE_BULLETS => {
            let add = bonus_apply_seconds(BONUS_ID_FIRE_BULLETS, amount) * economist_multiplier;
            state.player.fire_bullets_timer = (state.player.fire_bullets_timer + add) as f32;
            state.player.shot_cooldown = 0.0;
            state.player.reload_active = false;
            state.player.reload_timer = 0.0;
            state.player.reload_timer_max = 0.0;
            state.player.ammo = state.player.clip_size as f32;
        }
        BONUS_ID_SHOCK_CHAIN => {
            state.shock_chain_projectile_id = -1;
            state.shock_chain_links_left = 0x20;
            if let Some((target_idx, target)) = shock_chain_initial_target(state, origin) {
                let angle = (f64::from(target.y) - f64::from(origin.y))
                    .atan2(f64::from(target.x) - f64::from(origin.x))
                    + std::f64::consts::FRAC_PI_2;
                let angle_spawn = f64::from(angle as f32);
                if std::env::var("CRIMSON_RUST_DEBUG_SHOCK").is_ok() {
                    eprintln!(
                        "dbg shock_apply tick={} origin=({}, {}) target_idx={} target=({}, {}) angle={} angle_spawn={}",
                        state.debug_tick_index,
                        origin.x,
                        origin.y,
                        target_idx,
                        target.x,
                        target.y,
                        angle,
                        angle_spawn
                    );
                }
                let prev_guard = state.bonus_spawn_guard;
                state.bonus_spawn_guard = true;
                if let Some(proj_id) = spawn_bonus_projectile(
                    state,
                    origin,
                    angle_spawn,
                    PROJECTILE_TYPE_ION_RIFLE,
                    None,
                    -100,
                ) {
                    state.shock_chain_projectile_id = i32::try_from(proj_id).unwrap_or(-1);
                }
                state.bonus_spawn_guard = prev_guard;
            }
        }
        BONUS_ID_FIREBLAST => {
            let prev_guard = state.bonus_spawn_guard;
            state.bonus_spawn_guard = true;
            let count = 16_i32;
            let angle_step = std::f64::consts::TAU / f64::from(count);
            for idx in 0..count {
                let angle = f64::from(idx) * angle_step;
                let _ = spawn_bonus_projectile(
                    state,
                    origin,
                    angle,
                    PROJECTILE_TYPE_PLASMA_RIFLE,
                    None,
                    -100,
                );
            }
            state.bonus_spawn_guard = prev_guard;
        }
        BONUS_ID_NUKE => {
            state.camera_shake_pulses = 0x14;
            state.camera_shake_timer = 0.2;
            let bullet_count = i32::try_from(state.rng.rand() & 3).unwrap_or(0) + 4;
            for _ in 0..bullet_count {
                let angle = (state.rng.rand() % 0x274) as f32 * 0.01;
                let speed_scale = (state.rng.rand() % 0x32) as f32 * 0.01 + 0.5;
                let _ = spawn_bonus_projectile(
                    state,
                    origin,
                    f64::from(angle),
                    PROJECTILE_TYPE_PISTOL,
                    Some(speed_scale),
                    -100,
                );
                state.shots_fired = state.shots_fired.saturating_add(1);
            }
            for _ in 0..2 {
                let angle = (state.rng.rand() % 0x274) as f32 * 0.01;
                let _ = spawn_bonus_projectile(
                    state,
                    origin,
                    f64::from(angle),
                    PROJECTILE_TYPE_GAUSS_GUN,
                    None,
                    -100,
                );
                state.shots_fired = state.shots_fired.saturating_add(1);
            }
            consume_nuke_explosion_burst_rng(
                &mut state.rng,
                i32::try_from(state.detail_preset).unwrap_or(5),
            );

            let prev_guard = state.bonus_spawn_guard;
            state.bonus_spawn_guard = true;
            for idx in 0..state.creatures.len() {
                if !state.creatures[idx].active {
                    continue;
                }
                let delta = state.creatures[idx].pos.sub(origin);
                if delta.x.abs() > 256.0 || delta.y.abs() > 256.0 {
                    continue;
                }
                let dist = delta.length_sq().sqrt();
                if dist >= 256.0 {
                    continue;
                }
                let damage = (256.0 - dist) * 5.0;
                if damage <= 0.0 {
                    continue;
                }
                let mut reward_value = None;
                let mut death_pos = None;
                let mut death_sfx_draw = false;
                {
                    let creature = &mut state.creatures[idx];
                    if creature.health <= 0.0 {
                        if dt > 0.0 {
                            creature.lifecycle_stage =
                                (creature.lifecycle_stage - dt * 15.0) as f32;
                        }
                        continue;
                    }
                    creature.health -= damage;
                    if creature.health <= 0.0
                        && creature.lifecycle_stage == CREATURE_LIFECYCLE_ALIVE
                    {
                        creature.lifecycle_stage = if dt > 0.0 {
                            // Native death transition decrements hitbox in both
                            // `creature_apply_damage` and subsequent `creature_handle_death`.
                            let first =
                                (f64::from(creature.lifecycle_stage) - f64::from(dt)) as f32;
                            (f64::from(first) - f64::from(dt)) as f32
                        } else {
                            (f64::from(creature.lifecycle_stage) - 0.001_f64) as f32
                        };
                        reward_value = Some(creature.reward_value);
                        death_pos = Some(creature.pos);
                        death_sfx_draw = (creature.flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) == 0;
                    }
                }
                if let Some(reward) = reward_value {
                    let _ = award_player_xp_from_creature_reward(state, reward);
                    if let Some(pos) = death_pos {
                        let draws_before = state.rng.draw_count();
                        let spawned = bonus_try_spawn_on_kill(state, pos);
                        if spawned {
                            consume_spawn_burst_rng(&mut state.rng, 16);
                        }
                        let draws_after = state.rng.draw_count();
                        let delta = draws_after.saturating_sub(draws_before);
                        state.debug_bonus_flow_draws_tick = state
                            .debug_bonus_flow_draws_tick
                            .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));
                    }
                    if death_sfx_draw {
                        consume_death_sfx_draw_if_planned(state);
                    }
                    apply_freeze_kill_cleanup(state, idx);
                }
            }
            state.bonus_spawn_guard = prev_guard;
        }
        BONUS_ID_UNUSED => {}
        _ => {}
    }
}

fn shock_chain_initial_target(state: &SimState, origin: Vec2f) -> Option<(usize, Vec2f)> {
    if state.creatures.is_empty() {
        return None;
    }

    let mut best_idx = 0_usize;
    let mut best_dist_sq = 1.0e12_f64;
    for (idx, creature) in state.creatures.iter().enumerate() {
        if !creature.active {
            continue;
        }
        if creature.lifecycle_stage != CREATURE_LIFECYCLE_ALIVE {
            continue;
        }
        let dx = f64::from(creature.pos.x) - f64::from(origin.x);
        let dy = f64::from(creature.pos.y) - f64::from(origin.y);
        let dist_sq = dx * dx + dy * dy;
        if dist_sq < best_dist_sq {
            best_dist_sq = dist_sq;
            best_idx = idx;
        }
    }

    state
        .creatures
        .get(best_idx)
        .map(|creature| (best_idx, creature.pos))
}

fn spawn_bonus_projectile(
    state: &mut SimState,
    pos: Vec2f,
    angle: f64,
    type_id: i64,
    speed_scale: Option<f32>,
    owner_id: i64,
) -> Option<usize> {
    if state.projectiles.is_empty() {
        return None;
    }
    let (base_damage, damage_pool, hit_radius, life_timer) =
        projectile_init_fields_for_type(type_id);
    let mut projectile = RuntimeProjectile {
        active: true,
        pos,
        origin: pos,
        angle,
        type_id,
        owner_id,
        hits_players: false,
        base_damage,
        speed_scale: 1.0,
        damage_pool,
        hit_radius,
        life_timer,
    };
    if let Some(scale) = speed_scale {
        projectile.speed_scale *= scale;
    }
    let slot = state
        .projectiles
        .iter()
        .position(|entry| !entry.active)
        .unwrap_or(state.projectiles.len() - 1);
    state.projectiles[slot] = projectile;
    Some(slot)
}

fn consume_nuke_explosion_burst_rng(rng: &mut CrtRand, detail_preset: i32) {
    if detail_preset > 3 {
        let _ = rng.rand();
        let _ = rng.rand();
    }

    let count = if detail_preset < 2 {
        1
    } else {
        3 + if detail_preset > 3 { 1 } else { 0 }
    };
    for _ in 0..count {
        let _ = rng.rand();
        let _ = rng.rand();
        let _ = rng.rand();
        let _ = rng.rand();
        let _ = rng.rand();
    }
}

fn bonus_find_aim_hover_entry(state: &SimState) -> Option<usize> {
    let aim_pos = state.player.aim;
    let radius_sq = BONUS_AIM_HOVER_RADIUS * BONUS_AIM_HOVER_RADIUS;
    state
        .bonus_pool
        .iter()
        .enumerate()
        .find_map(|(idx, entry)| {
            if entry.bonus_id == BONUS_ID_UNUSED {
                return None;
            }
            if aim_pos.sub(entry.pos).length_sq() < radius_sq {
                return Some(idx);
            }
            None
        })
}

fn bonus_telekinetic_update(state: &mut SimState, dt: f32) {
    if dt <= 0.0 || state.player.health <= 0.0 {
        return;
    }
    let hovered = bonus_find_aim_hover_entry(state);
    let Some(idx) = hovered else {
        state.player.bonus_aim_hover_index = -1;
        state.player.bonus_aim_hover_timer_ms = 0.0;
        return;
    };

    state.player.bonus_aim_hover_index = i32::try_from(idx).unwrap_or(-1);
    state.player.bonus_aim_hover_timer_ms += dt * 1000.0;
    if state.player.bonus_aim_hover_timer_ms <= BONUS_TELEKINETIC_PICKUP_MS {
        return;
    }
    if !perk_active(&state.player, PERK_TELEKINETIC) {
        return;
    }
    if state.bonus_pool[idx].picked || state.bonus_pool[idx].bonus_id == BONUS_ID_UNUSED {
        return;
    }

    let bonus_id = state.bonus_pool[idx].bonus_id;
    let amount = state.bonus_pool[idx].amount;
    let origin = state.bonus_pool[idx].pos;
    bonus_apply(state, bonus_id, amount, origin, dt);
    consume_bonus_pickup_fx_rng(state, bonus_id);
    state.bonus_pool[idx].picked = true;
    state.bonus_pool[idx].time_left = BONUS_PICKUP_LINGER;
    state.player.bonus_aim_hover_index = -1;
    state.player.bonus_aim_hover_timer_ms = 0.0;
}

fn bonus_pool_update(state: &mut SimState, dt: f32) {
    if dt <= 0.0 {
        return;
    }
    let pickup_radius_sq = BONUS_PICKUP_RADIUS * BONUS_PICKUP_RADIUS;
    for idx in 0..state.bonus_pool.len() {
        if bonus_entry_is_empty(&state.bonus_pool[idx]) {
            continue;
        }

        let decay = dt
            * if state.bonus_pool[idx].picked {
                BONUS_PICKUP_DECAY_RATE
            } else {
                1.0
            };
        let time_left_after = f64::from(state.bonus_pool[idx].time_left) - f64::from(decay);
        state.bonus_pool[idx].time_left = time_left_after as f32;

        let mut expired_to_unused = false;
        let picked_entry = state.bonus_pool[idx].picked;
        let expired_now = if picked_entry {
            time_left_after <= 1e-6
        } else {
            time_left_after < 0.0
        };
        if expired_now {
            if picked_entry {
                bonus_clear_entry(&mut state.bonus_pool[idx]);
                continue;
            }
            state.bonus_pool[idx].bonus_id = BONUS_ID_UNUSED;
            expired_to_unused = true;
        }

        if state.bonus_pool[idx].picked {
            continue;
        }

        let mut picked_now = false;
        if state.bonus_pool[idx].pos.sub(state.player_pos).length_sq() < pickup_radius_sq {
            let bonus_id = state.bonus_pool[idx].bonus_id;
            let amount = state.bonus_pool[idx].amount;
            let origin = state.bonus_pool[idx].pos;
            bonus_apply(state, bonus_id, amount, origin, dt);
            consume_bonus_pickup_fx_rng(state, bonus_id);
            state.bonus_pool[idx].picked = true;
            state.bonus_pool[idx].time_left = BONUS_PICKUP_LINGER;
            picked_now = true;
        }

        if expired_to_unused && !picked_now {
            bonus_clear_entry(&mut state.bonus_pool[idx]);
        }
    }
}

fn consume_bonus_pickup_fx_rng(state: &mut SimState, bonus_id: i32) {
    if bonus_id == BONUS_ID_NUKE {
        return;
    }
    // Mirrors `emit_bonus_pickup_effects` default burst:
    // `effects.spawn_burst(count=12, scale_step=0.1)` => 3 draws per burst entry.
    for _ in 0..12 {
        let _ = state.rng.rand();
        let _ = state.rng.rand();
        let _ = state.rng.rand();
    }
}

fn bonus_update_pre_pickup_timers(bonuses: &mut BonusTimers, dt: f32) {
    if dt <= 0.0 {
        return;
    }
    if bonuses.weapon_power_up > 0.0 {
        bonuses.weapon_power_up = (f64::from(bonuses.weapon_power_up) - f64::from(dt)) as f32;
    }
    if bonuses.energizer > 0.0 {
        bonuses.energizer = (f64::from(bonuses.energizer) - f64::from(dt)) as f32;
    }
    if bonuses.reflex_boost > 0.0 {
        let reflex_before = bonuses.reflex_boost;
        let mut subtract = f64::from(dt);
        if reflex_before > 0.0 && reflex_before < 1.0 {
            subtract += REFLEX_TIMER_SUBTRACT_BIAS;
        }
        bonuses.reflex_boost = (f64::from(reflex_before) - subtract) as f32;
    }
}

fn bonus_update(state: &mut SimState, dt: f32) {
    bonus_telekinetic_update(state, dt);
    bonus_pool_update(state, dt);

    if dt > 0.0 {
        if state.bonuses.double_experience <= 0.0 {
            state.bonuses.double_experience = 0.0;
        } else {
            state.bonuses.double_experience =
                (f64::from(state.bonuses.double_experience) - f64::from(dt)) as f32;
        }
        if state.bonuses.freeze <= 0.0 {
            state.bonuses.freeze = 0.0;
        } else {
            state.bonuses.freeze = (f64::from(state.bonuses.freeze) - f64::from(dt)) as f32;
        }
    }
}

fn camera_shake_update(state: &mut SimState, dt: f32) {
    if state.camera_shake_timer <= 0.0 {
        state.camera_shake_offset = Vec2f { x: 0.0, y: 0.0 };
        return;
    }

    state.camera_shake_timer = (state.camera_shake_timer - dt * 3.0) as f32;
    if state.camera_shake_timer >= 0.0 {
        return;
    }

    state.camera_shake_pulses -= 1;
    if state.camera_shake_pulses < 1 {
        state.camera_shake_timer = 0.0;
        return;
    }

    let time_scale_active = state.bonuses.reflex_boost > 0.0;
    state.camera_shake_timer = if time_scale_active { 0.06 } else { 0.1 };

    let max_amp = state.camera_shake_pulses * 3;
    if max_amp <= 0 {
        state.camera_shake_offset = Vec2f { x: 0.0, y: 0.0 };
        state.camera_shake_timer = 0.0;
        state.camera_shake_pulses = 0;
        return;
    }

    let mut mag_x = (state.rng.rand() % max_amp as u32) as i32 + (state.rng.rand() % 10) as i32;
    if (state.rng.rand() & 1) == 0 {
        mag_x = -mag_x;
    }
    let mut mag_y = (state.rng.rand() % max_amp as u32) as i32 + (state.rng.rand() % 10) as i32;
    if (state.rng.rand() & 1) == 0 {
        mag_y = -mag_y;
    }
    state.camera_shake_offset = Vec2f {
        x: mag_x as f32,
        y: mag_y as f32,
    };
}

fn survival_runtime_tick(state: &mut SimState, dt_s: f32) {
    if dt_s <= 0.0 {
        return;
    }

    let debug_tick = std::env::var("CRIMSON_RUST_DEBUG_TICK")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    if debug_tick == Some(state.debug_tick_index) {
        eprintln!(
            "dbg tick={} rng_before_creatures={}",
            state.debug_tick_index,
            state.rng.state()
        );
    }
    survival_runtime_update_creatures(state, dt_s);
    if debug_tick == Some(state.debug_tick_index) {
        eprintln!(
            "dbg tick={} rng_after_creatures={}",
            state.debug_tick_index,
            state.rng.state()
        );
    }
    survival_runtime_update_projectiles(state, dt_s);
    if debug_tick == Some(state.debug_tick_index) {
        eprintln!(
            "dbg tick={} rng_after_projectiles={}",
            state.debug_tick_index,
            state.rng.state()
        );
    }
}

fn finalize_post_render_creature_lifecycle(state: &mut SimState) {
    for idx in 0..state.creatures.len() {
        if !state.creatures[idx].active {
            continue;
        }
        if state.creatures[idx].lifecycle_stage < CREATURE_CORPSE_DESPAWN_LIFECYCLE {
            state.creatures[idx].active = false;
        }
    }
}

fn creature_ai7_tick_link_timer(creature: &mut RuntimeCreature, dt_ms: i32, rng: &mut CrtRand) {
    if (creature.flags & CREATURE_FLAG_AI7_LINK_TIMER) == 0 {
        return;
    }

    if creature.link_index < 0 {
        creature.link_index += dt_ms;
        if creature.link_index >= 0 {
            creature.ai_mode = CREATURE_AI_MODE_HOLD_TIMER;
            creature.link_index = ((rng.rand() & 0x1FF) + 500) as i32;
        }
        return;
    }

    creature.link_index -= dt_ms;
    if creature.link_index < 1 {
        creature.link_index = -700 - (rng.rand() & 0x3FF) as i32;
    }
}

fn creature_distance_f32(a: Vec2f, b: Vec2f) -> f32 {
    let dx = (b.x - a.x) as f32;
    let dy = (b.y - a.y) as f32;
    ((dx * dx + dy * dy) as f64).sqrt() as f32
}

fn creature_orbit_target_f32(player_pos: Vec2f, orbit_phase: f32, dist: f32, scale: f32) -> Vec2f {
    let orbit_dist = (dist as f32 * scale as f32) as f32;
    let phase = orbit_phase as f32;
    let px = player_pos.x as f32;
    let py = player_pos.y as f32;
    let orbit_x = (f64::from(phase).cos()) as f32;
    let orbit_y = (f64::from(phase).sin()) as f32;
    Vec2f {
        x: (orbit_x * orbit_dist + px) as f32,
        y: (orbit_y * orbit_dist + py) as f32,
    }
}

fn creature_angle_approach(current: f64, target: f64, rate: f32, dt: f32) -> f64 {
    let mut angle = current;
    let target_f = target;
    let rate_f = f64::from(rate as f32);
    let dt_f = f64::from(dt as f32);
    let tau = 6.283_185_5_f64;

    while angle < 0.0 {
        angle += tau;
    }
    while tau < angle {
        angle -= tau;
    }

    let direct = (target_f - angle).abs();
    let hi = if angle < target_f { target_f } else { angle };
    let lo = if target_f < angle { target_f } else { angle };
    let wrapped = ((tau - hi) + lo).abs();

    let mut step_scale = if direct < wrapped { direct } else { wrapped };
    if 1.0 < step_scale {
        step_scale = 1.0;
    }
    let step_delta = dt_f * step_scale * rate_f;

    if direct <= wrapped {
        if angle < target_f {
            return angle + step_delta;
        }
    } else if target_f < angle {
        return angle + step_delta;
    }
    angle - step_delta
}

fn creature_movement_delta_from_heading_f32(
    heading: f64,
    dt: f32,
    move_scale: f32,
    move_speed: f32,
) -> Vec2f {
    let radians = f64::from(heading as f32) - f64::from(NATIVE_HALF_PI);

    let mut vx = radians.cos();
    vx *= f64::from(dt as f32);
    vx *= f64::from(move_scale as f32);
    vx *= f64::from(move_speed as f32);
    vx *= f64::from(SURVIVAL_RUNTIME_CREATURE_SPEED_SCALE);

    let mut vy = radians.sin();
    vy *= f64::from(dt as f32);
    vy *= f64::from(move_scale as f32);
    vy *= f64::from(move_speed as f32);
    vy *= f64::from(SURVIVAL_RUNTIME_CREATURE_SPEED_SCALE);

    Vec2f {
        x: vx as f32,
        y: vy as f32,
    }
}

fn resolve_live_link_pos(creatures: &[RuntimeCreature], link_index: i32) -> Option<Vec2f> {
    let idx = usize::try_from(link_index).ok()?;
    let creature = creatures.get(idx)?;
    if creature.health <= 0.0 {
        return None;
    }
    Some(creature.pos)
}

fn creature_ai_update_target(
    creature: &mut RuntimeCreature,
    player_pos: Vec2f,
    creatures: &[RuntimeCreature],
    dt: f32,
) {
    let dist_to_player = creature_distance_f32(creature.pos, player_pos);
    let orbit_phase = (((creature.phase_seed as i32 as f32) * 3.7) as f32 * NATIVE_PI) as f32;

    let mut move_scale = 1.0_f32;
    creature.force_target = 0;

    match creature.ai_mode {
        CREATURE_AI_MODE_ORBIT_PLAYER => {
            if dist_to_player > 800.0 {
                creature.target = player_pos;
            } else {
                creature.target =
                    creature_orbit_target_f32(player_pos, orbit_phase, dist_to_player, 0.85);
            }
        }
        CREATURE_AI_MODE_ORBIT_PLAYER_WIDE => {
            creature.target =
                creature_orbit_target_f32(player_pos, orbit_phase, dist_to_player, 0.9);
        }
        CREATURE_AI_MODE_ORBIT_PLAYER_TIGHT => {
            if dist_to_player > 800.0 {
                creature.target = player_pos;
            } else {
                creature.target =
                    creature_orbit_target_f32(player_pos, orbit_phase, dist_to_player, 0.55);
            }
        }
        CREATURE_AI_MODE_FOLLOW_LINK => {
            if let Some(link_pos) = resolve_live_link_pos(creatures, creature.link_index) {
                creature.target = Vec2f {
                    x: (link_pos.x + creature.target_offset.x) as f32,
                    y: (link_pos.y + creature.target_offset.y) as f32,
                };
            } else {
                creature.ai_mode = CREATURE_AI_MODE_ORBIT_PLAYER;
            }
        }
        CREATURE_AI_MODE_FOLLOW_LINK_TETHERED => {
            if let Some(link_pos) = resolve_live_link_pos(creatures, creature.link_index) {
                creature.target = Vec2f {
                    x: (link_pos.x + creature.target_offset.x) as f32,
                    y: (link_pos.y + creature.target_offset.y) as f32,
                };
                let dist_to_target = creature_distance_f32(creature.pos, creature.target);
                if dist_to_target <= 64.0 {
                    move_scale = (dist_to_target * 0.015_625) as f32;
                }
            } else {
                creature.ai_mode = CREATURE_AI_MODE_ORBIT_PLAYER;
            }
        }
        _ => {}
    }

    match creature.ai_mode {
        CREATURE_AI_MODE_LINK_GUARD => {
            if resolve_live_link_pos(creatures, creature.link_index).is_none() {
                creature.ai_mode = CREATURE_AI_MODE_ORBIT_PLAYER;
            } else if dist_to_player > 800.0 {
                creature.target = player_pos;
            } else {
                creature.target =
                    creature_orbit_target_f32(player_pos, orbit_phase, dist_to_player, 0.85);
            }
        }
        CREATURE_AI_MODE_HOLD_TIMER => {
            if (creature.flags & CREATURE_FLAG_AI7_LINK_TIMER) != 0 && creature.link_index > 0 {
                creature.target = creature.pos;
            } else if (creature.flags & CREATURE_FLAG_AI7_LINK_TIMER) == 0
                && creature.orbit_radius > 0.0
            {
                creature.target = creature.pos;
                creature.orbit_radius = (creature.orbit_radius - dt) as f32;
            } else {
                creature.ai_mode = CREATURE_AI_MODE_ORBIT_PLAYER;
            }
        }
        CREATURE_AI_MODE_ORBIT_LINK => {
            if let Some(link_pos) = resolve_live_link_pos(creatures, creature.link_index) {
                let angle = f64::from(creature.orbit_angle) + creature.heading;
                creature.target = Vec2f {
                    x: (angle.cos() * f64::from(creature.orbit_radius) + f64::from(link_pos.x))
                        as f32,
                    y: (angle.sin() * f64::from(creature.orbit_radius) + f64::from(link_pos.y))
                        as f32,
                };
            } else {
                creature.ai_mode = CREATURE_AI_MODE_ORBIT_PLAYER;
            }
        }
        _ => {}
    }

    let dist_to_target = creature_distance_f32(creature.pos, creature.target);
    if dist_to_target < 40.0 || dist_to_target > 400.0 {
        creature.force_target = 1;
    }

    if creature.force_target != 0 || creature.ai_mode == CREATURE_AI_MODE_CHASE_PLAYER {
        creature.target = player_pos;
    }

    creature.target_heading = f64::from(heading_from_direction_native(
        creature.target.sub(creature.pos),
    ));
    creature.move_scale = move_scale as f32;
}

fn runtime_creature_is_collidable(creature: &RuntimeCreature) -> bool {
    creature.active && creature.lifecycle_stage > 5.0
}

fn runtime_tick_dead_creature(creature: &mut RuntimeCreature, dt: f32) -> bool {
    if dt <= 0.0 {
        return false;
    }

    let hitbox = creature.lifecycle_stage as f32;
    if hitbox <= 0.0 {
        creature.lifecycle_stage = (hitbox - dt * CREATURE_CORPSE_FADE_DECAY) as f32;
        return false;
    }

    let new_hitbox = (hitbox - dt * CREATURE_DEATH_TIMER_DECAY) as f32;
    creature.lifecycle_stage = new_hitbox;
    if new_hitbox > 0.0 {
        let long_strip = (creature.flags & CREATURE_FLAG_ANIM_PING_PONG) == 0
            || (creature.flags & CREATURE_FLAG_ANIM_LONG_STRIP) != 0;
        if long_strip {
            let slide = (new_hitbox * dt * CREATURE_DEATH_SLIDE_SCALE) as f32;
            let direction = direction_from_heading_native(creature.heading as f32);
            creature.vel = direction.scale(slide);
            creature.pos = creature.pos.sub(creature.vel);
        } else {
            creature.vel = Vec2f { x: 0.0, y: 0.0 };
        }
        return false;
    }

    true
}

fn creature_type_has_contact_sfx(type_id: i32) -> bool {
    matches!(
        type_id,
        CREATURE_TYPE_ZOMBIE
            | CREATURE_TYPE_LIZARD
            | CREATURE_TYPE_ALIEN
            | CREATURE_TYPE_SPIDER_SP1
            | CREATURE_TYPE_SPIDER_SP2
    )
}

fn player_take_damage(state: &mut SimState, raw_damage: f32, dt_s: f32) -> f32 {
    if raw_damage <= 0.0 {
        return 0.0;
    }
    if perk_active(&state.player, PERK_DEATH_CLOCK) {
        return 0.0;
    }

    let mut damage_scaled = raw_damage;
    if perk_active(&state.player, PERK_TOUGH_RELOADER) && state.player.reload_active {
        damage_scaled = (damage_scaled * 0.5) as f32;
    }
    let spread_heat_damage = damage_scaled;

    if state.player.shield_timer > 0.0 {
        return 0.0;
    }

    let was_alive = state.player.health > 0.0;
    if perk_active(&state.player, PERK_THICK_SKINNED) {
        damage_scaled =
            (f64::from(damage_scaled) * f64::from(PLAYER_THICK_SKINNED_DAMAGE_SCALE_F32)) as f32;
    }

    let mut dodged = false;
    if perk_active(&state.player, PERK_NINJA) {
        dodged = (state.rng.rand() % 3) == 0;
    } else if perk_active(&state.player, PERK_DODGER) {
        dodged = (state.rng.rand() % 5) == 0;
    }

    let health_before = state.player.health;
    if !dodged {
        if perk_active(&state.player, PERK_HIGHLANDER) {
            if (state.rng.rand() % 10) == 0 {
                state.player.health = 0.0;
            }
        } else {
            state.player.health =
                (f64::from(state.player.health) - f64::from(damage_scaled)) as f32;
            if state.player.health < 0.0 && dt_s > 0.0 {
                // Native decrements `death_timer` here; phase-1 verifier currently
                // does not model that timer.
            }
        }
    }

    if state.player.health >= 0.0 {
        let _ = state.rng.rand();
        if !was_alive {
            return (health_before - state.player.health).max(0.0);
        }
    } else if !was_alive {
        return (health_before - state.player.health).max(0.0);
    } else if !perk_active(&state.player, PERK_FINAL_REVENGE) {
        let _ = state.rng.rand();
    }

    if !dodged {
        if !perk_active(&state.player, PERK_UNSTOPPABLE) {
            // Python parity: heading jitter is computed in f64 (`int * 0.04`) and
            // only quantized when written back to the native-like f32 slot.
            let jitter =
                (i32::try_from(state.rng.rand() % 100).unwrap_or(0) - 50) as f64 * 0.04_f64;
            state.player.heading = (f64::from(state.player.heading) + jitter) as f32;
            state.player.spread_heat =
                (state.player.spread_heat + f64::from(spread_heat_damage) * 0.01).min(0.48);
        }
        if state.player.health <= 20.0 {
            if (state.rng.rand() & 7) == 3 {
                // Native zeros `low_health_timer` here; phase-1 verifier does not model it.
            }
        }
    }

    (health_before - state.player.health).max(0.0)
}

fn consume_creature_lethal_ranged_shock_burst_rng(rng: &mut CrtRand) {
    for _ in 0..5 {
        let _ = rng.rand();
        let _ = rng.rand();
        let _ = rng.rand();
        let _ = rng.rand();
    }
}

fn consume_death_sfx_draw_if_planned(state: &mut SimState) {
    if state.planned_death_sfx_draws_tick >= DEATH_SFX_PER_TICK_CAP {
        return;
    }
    let _ = state.rng.rand();
    state.planned_death_sfx_draws_tick = state.planned_death_sfx_draws_tick.saturating_add(1);
    state.debug_death_sfx_draws_tick = state.debug_death_sfx_draws_tick.saturating_add(1);
}

fn queue_creature_phase_death_sfx_draw(state: &mut SimState) {
    state.pending_creature_phase_death_sfx_draws = state
        .pending_creature_phase_death_sfx_draws
        .saturating_add(1);
}

fn flush_creature_phase_death_sfx_draws(state: &mut SimState) {
    let queued = state.pending_creature_phase_death_sfx_draws.max(0);
    state.pending_creature_phase_death_sfx_draws = 0;
    for _ in 0..queued {
        consume_death_sfx_draw_if_planned(state);
    }
}

fn creature_award_death_side_effects(
    state: &mut SimState,
    creature_idx: usize,
    reward_value: f32,
    death_pos: Vec2f,
    death_sfx_draw: bool,
) {
    let _ = award_player_xp_from_creature_reward(state, reward_value);
    let draws_before = state.rng.draw_count();
    let spawned = bonus_try_spawn_on_kill(state, death_pos);
    if spawned {
        consume_spawn_burst_rng(&mut state.rng, 16);
    }
    let draws_after = state.rng.draw_count();
    let delta = draws_after.saturating_sub(draws_before);
    state.debug_bonus_flow_draws_tick = state
        .debug_bonus_flow_draws_tick
        .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));

    if death_sfx_draw {
        queue_creature_phase_death_sfx_draw(state);
    }
    apply_freeze_kill_cleanup(state, creature_idx);
}

fn creature_apply_self_damage_tick(state: &mut SimState, creature_idx: usize, dt_s: f32) -> bool {
    if dt_s <= 0.0 || state.bonuses.freeze > 0.0 {
        return false;
    }
    if creature_idx >= state.creatures.len() || !state.creatures[creature_idx].active {
        return false;
    }

    let flags = state.creatures[creature_idx].flags;
    let damage_amount = if (flags & CREATURE_FLAG_SELF_DAMAGE_TICK_STRONG) != 0 {
        dt_s * 180.0
    } else if (flags & CREATURE_FLAG_SELF_DAMAGE_TICK) != 0 {
        dt_s * 60.0
    } else {
        0.0
    };
    if damage_amount <= 0.0 {
        return false;
    }

    let mut death_transition = false;
    let mut reward_value = 0.0_f32;
    let mut death_pos = Vec2f { x: 0.0, y: 0.0 };
    let mut death_sfx_draw = false;
    let mut ranged_shock_death = false;

    {
        let creature = &mut state.creatures[creature_idx];
        if creature.health <= 0.0 {
            creature.lifecycle_stage =
                (f64::from(creature.lifecycle_stage) - f64::from(dt_s) * 15.0) as f32;
            return false;
        }

        creature.health -= damage_amount;
        if creature.health <= 0.0 && creature.lifecycle_stage == CREATURE_LIFECYCLE_ALIVE {
            creature.lifecycle_stage = if dt_s > 0.0 {
                // `creature_apply_damage` and `creature_handle_death` each decrement
                // by frame dt when transitioning into corpse state.
                let first = (f64::from(creature.lifecycle_stage) - f64::from(dt_s)) as f32;
                (f64::from(first) - f64::from(dt_s)) as f32
            } else {
                (f64::from(creature.lifecycle_stage) - 0.001_f64) as f32
            };
            reward_value = creature.reward_value;
            death_pos = creature.pos;
            death_sfx_draw = (creature.flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) == 0;
            ranged_shock_death = (creature.flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0;
            death_transition = true;
        }
    }

    if !death_transition {
        return false;
    }
    if ranged_shock_death {
        consume_creature_lethal_ranged_shock_burst_rng(&mut state.rng);
    }
    creature_award_death_side_effects(state, creature_idx, reward_value, death_pos, death_sfx_draw);
    true
}

fn survival_runtime_update_creatures(state: &mut SimState, dt_s: f32) {
    if state.bonuses.freeze > 0.0 {
        return;
    }
    let debug_tick = std::env::var("CRIMSON_RUST_DEBUG_TICK")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    let dt_ms = if dt_s > 0.0 {
        (dt_s * 1000.0).round() as i32
    } else {
        0
    };
    let player_pos = state.player_pos;

    let mut creatures_snapshot = state.creatures.clone();
    for idx in 0..state.creatures.len() {
        if !state.creatures[idx].active {
            creatures_snapshot[idx] = state.creatures[idx];
            continue;
        }
        let debug_this_tick = debug_tick == Some(state.debug_tick_index);
        let rng_before_self = state.rng.state();
        let poison_killed = creature_apply_self_damage_tick(state, idx, dt_s);
        if debug_this_tick && state.rng.state() != rng_before_self {
            eprintln!(
                "dbg tick={} creature_idx={} rng_self_damage: {} -> {}",
                state.debug_tick_index,
                idx,
                rng_before_self,
                state.rng.state()
            );
        }
        let rng_before_ai7 = state.rng.state();
        creature_ai7_tick_link_timer(&mut state.creatures[idx], dt_ms, &mut state.rng);
        if debug_this_tick && state.rng.state() != rng_before_ai7 {
            eprintln!(
                "dbg tick={} creature_idx={} rng_ai7: {} -> {}",
                state.debug_tick_index,
                idx,
                rng_before_ai7,
                state.rng.state()
            );
        }
        if state.creatures[idx].lifecycle_stage != CREATURE_LIFECYCLE_ALIVE
            || state.creatures[idx].health <= 0.0
        {
            if state.creatures[idx].lifecycle_stage == CREATURE_LIFECYCLE_ALIVE {
                state.creatures[idx].lifecycle_stage =
                    (f64::from(state.creatures[idx].lifecycle_stage) - f64::from(dt_s)) as f32;
            }
            if runtime_tick_dead_creature(&mut state.creatures[idx], dt_s) {
                state.creature_kill_count = state.creature_kill_count.saturating_add(1);
            }
            creatures_snapshot[idx] = state.creatures[idx];
            continue;
        }
        if dt_s <= 0.0 {
            creatures_snapshot[idx] = state.creatures[idx];
            continue;
        }
        if poison_killed {
            if state.creatures[idx].active
                && runtime_tick_dead_creature(&mut state.creatures[idx], dt_s)
            {
                state.creature_kill_count = state.creature_kill_count.saturating_add(1);
            }
            creatures_snapshot[idx] = state.creatures[idx];
            continue;
        }

        creature_ai_update_target(
            &mut state.creatures[idx],
            player_pos,
            &creatures_snapshot,
            dt_s,
        );

        if (state.creatures[idx].flags & CREATURE_FLAG_ANIM_PING_PONG) == 0
            && state.creatures[idx].ai_mode != CREATURE_AI_MODE_HOLD_TIMER
        {
            let turn_rate = (state.creatures[idx].move_speed * NATIVE_TURN_RATE_SCALE) as f32;
            state.creatures[idx].heading = creature_angle_approach(
                state.creatures[idx].heading,
                state.creatures[idx].target_heading,
                turn_rate,
                dt_s,
            );
            let delta = creature_movement_delta_from_heading_f32(
                state.creatures[idx].heading,
                dt_s,
                state.creatures[idx].move_scale,
                state.creatures[idx].move_speed,
            );
            state.creatures[idx].vel = delta;
            state.creatures[idx].pos = state.creatures[idx].pos.add(delta);
        }

        let eat_dist_sq = state.creatures[idx].pos.sub(player_pos).length_sq();
        if eat_dist_sq < 20.0 * 20.0 {
            let mut reverted = state.creatures[idx].pos.sub(state.creatures[idx].vel);
            let max_x = state.survival_terrain_width as f32;
            let max_y = state.survival_terrain_height as f32;
            reverted.x = reverted.x.clamp(0.0, max_x);
            reverted.y = reverted.y.clamp(0.0, max_y);
            state.creatures[idx].pos = reverted;
        }

        if state.creatures[idx].attack_cooldown <= 0.0 {
            state.creatures[idx].attack_cooldown = 0.0;
        } else {
            state.creatures[idx].attack_cooldown =
                (state.creatures[idx].attack_cooldown - dt_s) as f32;
        }

        let contact_dist_sq = state.creatures[idx].pos.sub(player_pos).length_sq();
        let dist_to_player = contact_dist_sq.sqrt();
        let ranged_flags = state.creatures[idx].flags
            & (CREATURE_FLAG_RANGED_ATTACK_SHOCK | CREATURE_FLAG_RANGED_ATTACK_VARIANT);
        if debug_this_tick && ranged_flags != 0 {
            eprintln!(
                "dbg tick={} creature_idx={} ranged_flags={:#x} dist={} atk_cd={} orbit_radius={} orbit_angle={}",
                state.debug_tick_index,
                idx,
                ranged_flags,
                dist_to_player,
                state.creatures[idx].attack_cooldown,
                state.creatures[idx].orbit_radius,
                state.creatures[idx].orbit_angle
            );
        }
        if ranged_flags != 0 && dist_to_player > 64.0 && state.creatures[idx].attack_cooldown <= 0.0
        {
            if (state.creatures[idx].flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0 {
                let creature_pos = state.creatures[idx].pos;
                let creature_heading = state.creatures[idx].heading;
                if let Some(proj_idx) = spawn_bonus_projectile(
                    state,
                    creature_pos,
                    creature_heading,
                    PROJECTILE_TYPE_PLASMA_RIFLE,
                    None,
                    i64::try_from(idx).unwrap_or(i64::MAX),
                ) {
                    state.projectiles[proj_idx].hits_players = true;
                }
                state.creatures[idx].attack_cooldown =
                    (f64::from(state.creatures[idx].attack_cooldown) + 1.0_f64) as f32;
            }

            if (state.creatures[idx].flags & CREATURE_FLAG_RANGED_ATTACK_VARIANT) != 0
                && state.creatures[idx].attack_cooldown <= 0.0
            {
                let creature_pos = state.creatures[idx].pos;
                let creature_heading = state.creatures[idx].heading;
                let projectile_type = state.creatures[idx].orbit_radius as i64;
                if let Some(proj_idx) = spawn_bonus_projectile(
                    state,
                    creature_pos,
                    creature_heading,
                    projectile_type,
                    None,
                    i64::try_from(idx).unwrap_or(i64::MAX),
                ) {
                    state.projectiles[proj_idx].hits_players = true;
                }
                let cooldown = f64::from(state.rng.rand() & 3) * 0.1_f64
                    + f64::from(state.creatures[idx].orbit_angle)
                    + f64::from(state.creatures[idx].attack_cooldown);
                state.creatures[idx].attack_cooldown = cooldown as f32;
            }
        }

        let can_contact_damage = state.creatures[idx].lifecycle_stage == CREATURE_LIFECYCLE_ALIVE
            && state.creatures[idx].size > 16.0
            && state.bonuses.energizer <= 0.0
            && contact_dist_sq < 30.0 * 30.0
            && state.player.health > 0.0
            && state.creatures[idx].attack_cooldown <= 0.0;
        if can_contact_damage {
            let rng_before_contact = state.rng.state();
            if creature_type_has_contact_sfx(state.creatures[idx].type_id) {
                let _ = state.rng.rand();
            }
            let _ = player_take_damage(state, state.creatures[idx].contact_damage, dt_s);
            consume_fx_queue_add_random_rng(&mut state.rng);
            state.creatures[idx].attack_cooldown =
                (state.creatures[idx].attack_cooldown + 1.0) as f32;
            if debug_this_tick && state.rng.state() != rng_before_contact {
                eprintln!(
                    "dbg tick={} creature_idx={} rng_contact: {} -> {}",
                    state.debug_tick_index,
                    idx,
                    rng_before_contact,
                    state.rng.state()
                );
            }
        }

        if state.creatures[idx].lifecycle_stage == CREATURE_LIFECYCLE_ALIVE
            && contact_dist_sq < 30.0 * 30.0
            && state.creatures[idx].size <= 30.0
        {
            state.creatures[idx].health = 0.0;
            state.creatures[idx].lifecycle_stage =
                (f64::from(state.creatures[idx].lifecycle_stage) - f64::from(dt_s)) as f32;
            creatures_snapshot[idx] = state.creatures[idx];
            continue;
        }

        creatures_snapshot[idx] = state.creatures[idx];
    }
    // Python parity: creature-phase death SFX draws are planned after the full
    // creature pass, before projectile update.
    flush_creature_phase_death_sfx_draws(state);
}

fn apply_bullet_damage_perk_scale(state: &SimState, damage: f32) -> f32 {
    let mut scaled = damage;
    if perk_active(&state.player, PERK_URANIUM_FILLED_BULLETS) {
        scaled *= 2.0;
    }
    if perk_active(&state.player, PERK_BARREL_GREASER) {
        scaled *= 1.4;
    }
    if perk_active(&state.player, PERK_DOCTOR) {
        scaled *= 1.2;
    }
    scaled
}

fn apply_projectile_hit_poison_bullets(
    state: &mut SimState,
    proj_owner_id: i64,
    creature_idx: usize,
) {
    if proj_owner_id >= 0 {
        return;
    }
    if !perk_active(&state.player, PERK_POISON_BULLETS) {
        return;
    }
    if (state.rng.rand() & 7) == 1 && creature_idx < state.creatures.len() {
        state.creatures[creature_idx].flags |= CREATURE_FLAG_SELF_DAMAGE_TICK;
    }
}

fn ion_linger_damage_params(state: &SimState, type_id: i64, dt_s: f32) -> Option<(f32, f32)> {
    let ion_scale = if perk_active(&state.player, PERK_ION_GUN_MASTER) {
        1.2_f32
    } else {
        1.0_f32
    };
    let (damage, radius) = match type_id {
        PROJECTILE_TYPE_ION_MINIGUN => (dt_s * 40.0, ion_scale * 60.0),
        PROJECTILE_TYPE_ION_RIFLE => (dt_s * 100.0, ion_scale * 88.0),
        PROJECTILE_TYPE_ION_CANNON => (dt_s * 300.0, ion_scale * 128.0),
        _ => return None,
    };
    Some((damage, radius))
}

fn apply_ion_linger_damage(state: &mut SimState, creature_idx: usize, damage: f32, dt_s: f32) {
    if creature_idx >= state.creatures.len() {
        return;
    }
    if !state.creatures[creature_idx].active {
        return;
    }

    if state.creatures[creature_idx].health <= 0.0 {
        if dt_s > 0.0 {
            state.creatures[creature_idx].lifecycle_stage =
                (f64::from(state.creatures[creature_idx].lifecycle_stage) - f64::from(dt_s * 15.0))
                    as f32;
        }
        return;
    }

    if damage <= 0.0 {
        return;
    }

    let mut reward_value = None;
    let mut death_pos = None;
    let mut death_sfx_draw = false;
    {
        let creature = &mut state.creatures[creature_idx];
        creature.health -= damage;
        if creature.health <= 0.0 && creature.lifecycle_stage == CREATURE_LIFECYCLE_ALIVE {
            creature.lifecycle_stage = if dt_s > 0.0 {
                let first = (f64::from(creature.lifecycle_stage) - f64::from(dt_s)) as f32;
                (f64::from(first) - f64::from(dt_s)) as f32
            } else {
                (f64::from(creature.lifecycle_stage) - 0.001_f64) as f32
            };
            reward_value = Some(creature.reward_value);
            death_pos = Some(creature.pos);
            death_sfx_draw = (creature.flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) == 0;
        }
    }

    if let Some(reward) = reward_value {
        let _ = award_player_xp_from_creature_reward(state, reward);
        if let Some(pos) = death_pos {
            let draws_before = state.rng.draw_count();
            let spawned = bonus_try_spawn_on_kill(state, pos);
            if spawned {
                consume_spawn_burst_rng(&mut state.rng, 16);
            }
            let draws_after = state.rng.draw_count();
            let delta = draws_after.saturating_sub(draws_before);
            state.debug_bonus_flow_draws_tick = state
                .debug_bonus_flow_draws_tick
                .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));
        }
        if death_sfx_draw {
            consume_death_sfx_draw_if_planned(state);
        }
        apply_freeze_kill_cleanup(state, creature_idx);
    }
}

fn apply_freeze_kill_cleanup(state: &mut SimState, creature_idx: usize) {
    if state.bonuses.freeze <= 0.0 {
        return;
    }
    if creature_idx >= state.creatures.len() {
        return;
    }
    if !state.creatures[creature_idx].active {
        return;
    }
    consume_bonus_freeze_corpse_shatter_rng(&mut state.rng);
    consume_fx_queue_add_random_rng(&mut state.rng);
    state.creature_kill_count = state.creature_kill_count.saturating_add(1);
    state.creatures[creature_idx].active = false;
}

fn survival_runtime_update_projectiles(state: &mut SimState, dt_s: f32) {
    let min_x = -SURVIVAL_RUNTIME_PROJECTILE_MARGIN;
    let min_y = -SURVIVAL_RUNTIME_PROJECTILE_MARGIN;
    let max_x = state.survival_terrain_width as f32 + SURVIVAL_RUNTIME_PROJECTILE_MARGIN;
    let max_y = state.survival_terrain_height as f32 + SURVIVAL_RUNTIME_PROJECTILE_MARGIN;
    let debug_tick = std::env::var("CRIMSON_RUST_DEBUG_TICK")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    let debug_proj = std::env::var("CRIMSON_RUST_DEBUG_PROJ")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());

    for proj_idx in 0..state.projectiles.len() {
        if !state.projectiles[proj_idx].active {
            continue;
        }

        if state.projectiles[proj_idx].life_timer <= 0.0 {
            state.projectiles[proj_idx].active = false;
        }
        if state.projectiles[proj_idx].life_timer < 0.4 {
            if let Some((ion_damage, ion_radius)) =
                ion_linger_damage_params(state, state.projectiles[proj_idx].type_id, dt_s)
            {
                let proj_pos = state.projectiles[proj_idx].pos;
                let mut hit_indices: Vec<usize> = Vec::new();
                for creature_idx in 0..state.creatures.len() {
                    if !state.creatures[creature_idx].active {
                        continue;
                    }
                    if state.creatures[creature_idx].lifecycle_stage <= 5.0 {
                        continue;
                    }
                    let creature_radius =
                        runtime_creature_hit_radius(state.creatures[creature_idx].size);
                    let hit_r = ion_radius + creature_radius;
                    if state.creatures[creature_idx].pos.sub(proj_pos).length_sq() <= hit_r * hit_r
                    {
                        hit_indices.push(creature_idx);
                    }
                }
                for creature_idx in hit_indices {
                    apply_ion_linger_damage(state, creature_idx, ion_damage, dt_s);
                }
            }
            if matches!(
                state.projectiles[proj_idx].type_id,
                PROJECTILE_TYPE_ION_RIFLE | PROJECTILE_TYPE_ION_MINIGUN
            ) && state.shock_chain_projectile_id == i32::try_from(proj_idx).unwrap_or(-1)
            {
                state.shock_chain_projectile_id = -1;
                state.shock_chain_links_left = 0;
            }
            let linger_dt = match state.projectiles[proj_idx].type_id {
                PROJECTILE_TYPE_GAUSS_GUN => dt_s * 0.1,
                PROJECTILE_TYPE_ION_CANNON => dt_s * 0.7,
                _ => dt_s,
            };
            state.projectiles[proj_idx].life_timer -= linger_dt;
            continue;
        }

        let proj_pos = state.projectiles[proj_idx].pos;
        if proj_pos.x < min_x || proj_pos.y < min_y || proj_pos.x > max_x || proj_pos.y > max_y {
            state.projectiles[proj_idx].life_timer -= dt_s;
            continue;
        }

        let mut steps = state.projectiles[proj_idx].base_damage as i32;
        if steps <= 0 {
            steps = 1;
        }
        if perk_active(&state.player, PERK_BARREL_GREASER)
            && state.projectiles[proj_idx].owner_id < 0
        {
            steps *= 2;
        }

        let movement_angle = state.projectiles[proj_idx].angle;
        let direction_radians = movement_angle - std::f64::consts::FRAC_PI_2;
        let direction_x = direction_radians.cos();
        let direction_y = direction_radians.sin();
        let mut acc = Vec2f { x: 0.0, y: 0.0 };
        let mut step = 0_i32;
        while step < steps {
            let step_scale =
                (f64::from(dt_s) * 20.0 * f64::from(state.projectiles[proj_idx].speed_scale) * 3.0)
                    as f32;
            acc = Vec2f {
                x: (f64::from(acc.x) + direction_x * f64::from(step_scale)) as f32,
                y: (f64::from(acc.y) + direction_y * f64::from(step_scale)) as f32,
            };
            let acc_len =
                (f64::from(acc.x) * f64::from(acc.x) + f64::from(acc.y) * f64::from(acc.y)).sqrt();
            if debug_tick == Some(state.debug_tick_index) && debug_proj == Some(proj_idx) {
                eprintln!(
                    "dbg tick={} proj={} step={} angle={} step_scale={} dir=({}, {}) acc=({}, {}) acc_len={}",
                    state.debug_tick_index,
                    proj_idx,
                    step,
                    state.projectiles[proj_idx].angle,
                    step_scale,
                    direction_x,
                    direction_y,
                    acc.x,
                    acc.y,
                    acc_len
                );
            }
            if acc_len >= 4.0 || steps <= step + 3 {
                let move_delta = acc;
                acc = Vec2f { x: 0.0, y: 0.0 };
                let proj_pos = state.projectiles[proj_idx].pos;
                state.projectiles[proj_idx].pos = Vec2f {
                    x: (f64::from(proj_pos.x) + f64::from(move_delta.x)) as f32,
                    y: (f64::from(proj_pos.y) + f64::from(move_delta.y)) as f32,
                };

                let mut hit_creature_idx: Option<usize> = None;
                let hit_origin = state.projectiles[proj_idx].pos;
                let hit_radius = state.projectiles[proj_idx].hit_radius;
                for creature_idx in 0..state.creatures.len() {
                    let creature = &state.creatures[creature_idx];
                    if !runtime_creature_is_collidable(creature) {
                        continue;
                    }
                    if runtime_within_native_find_radius(
                        hit_origin,
                        creature.pos,
                        hit_radius,
                        creature.size,
                    ) {
                        hit_creature_idx = Some(creature_idx);
                        break;
                    }
                }

                let Some(creature_idx) = hit_creature_idx else {
                    let can_hit_players =
                        state.shock_chain_projectile_id != i32::try_from(proj_idx).unwrap_or(-1);
                    if state.projectiles[proj_idx].hits_players
                        && can_hit_players
                        && state.player.health > 0.0
                        && runtime_within_native_find_radius(
                            hit_origin,
                            state.player_pos,
                            hit_radius,
                            state.player.size,
                        )
                    {
                        state.projectiles[proj_idx].life_timer = 0.25;
                        if state.player.shield_timer <= 0.0 {
                            state.player.health -= 10.0;
                        }
                        step += 3;
                        continue;
                    }
                    step += 3;
                    continue;
                };
                let owner_creature_idx = state.projectiles[proj_idx].owner_id;
                if i64::try_from(creature_idx).unwrap_or(i64::MAX) == owner_creature_idx {
                    step += 3;
                    continue;
                }
                if debug_tick == Some(state.debug_tick_index) && debug_proj == Some(proj_idx) {
                    eprintln!(
                        "dbg tick={} proj={} hit creature={} pos=({}, {}) target=({}, {}) size={} hitbox={}",
                        state.debug_tick_index,
                        proj_idx,
                        creature_idx,
                        state.projectiles[proj_idx].pos.x,
                        state.projectiles[proj_idx].pos.y
                        ,
                        state.creatures[creature_idx].pos.x,
                        state.creatures[creature_idx].pos.y,
                        state.creatures[creature_idx].size,
                        state.creatures[creature_idx].lifecycle_stage
                    );
                }

                let hit_target_pos = state.creatures[creature_idx].pos;
                state.debug_projectile_hits_tick =
                    state.debug_projectile_hits_tick.saturating_add(1);
                if state.debug_projectile_hits_detail_tick.len() < 32 {
                    let target_size = state.creatures[creature_idx].size;
                    state
                        .debug_projectile_hits_detail_tick
                        .push(ProjectileHitDebug {
                            projectile_index: proj_idx,
                            creature_index: creature_idx,
                            type_id: state.projectiles[proj_idx].type_id,
                            hit_pos: state.projectiles[proj_idx].pos,
                            target_pos: hit_target_pos,
                            target_size,
                        });
                }
                let owner_id = state.projectiles[proj_idx].owner_id;
                if owner_id < 0
                    && state.creatures[creature_idx].lifecycle_stage == CREATURE_LIFECYCLE_ALIVE
                {
                    state.shots_hit = state.shots_hit.saturating_add(1);
                }
                let type_id = state.projectiles[proj_idx].type_id;
                apply_projectile_hit_poison_bullets(state, owner_id, creature_idx);
                let rng_before_pre = state.rng.state();
                consume_projectile_hit_pre_rng(state);
                if debug_tick == Some(state.debug_tick_index) && debug_proj == Some(proj_idx) {
                    eprintln!(
                        "dbg tick={} proj={} rng_pre_hit: {} -> {}",
                        state.debug_tick_index,
                        proj_idx,
                        rng_before_pre,
                        state.rng.state()
                    );
                }
                if state.projectiles[proj_idx].life_timer != 0.25
                    && !projectile_is_piercing_type(type_id)
                {
                    state.projectiles[proj_idx].life_timer = 0.25;
                    let jitter_draw = state.rng.rand();
                    let jitter = (jitter_draw & 3) as f32;
                    let pos = state.projectiles[proj_idx].pos;
                    state.projectiles[proj_idx].pos = Vec2f {
                        x: (f64::from(pos.x) + direction_x * f64::from(jitter)) as f32,
                        y: (f64::from(pos.y) + direction_y * f64::from(jitter)) as f32,
                    };
                    if debug_tick == Some(state.debug_tick_index) && debug_proj == Some(proj_idx) {
                        eprintln!(
                            "dbg tick={} proj={} jitter_draw={} jitter={} pos_after=({}, {})",
                            state.debug_tick_index,
                            proj_idx,
                            jitter_draw,
                            jitter,
                            state.projectiles[proj_idx].pos.x,
                            state.projectiles[proj_idx].pos.y
                        );
                    }
                }

                let mut dist = state.projectiles[proj_idx]
                    .origin
                    .sub(state.projectiles[proj_idx].pos)
                    .length_sq()
                    .sqrt();
                if dist < 50.0 {
                    dist = 50.0;
                }
                if type_id == PROJECTILE_TYPE_ION_RIFLE
                    && state.shock_chain_projectile_id == i32::try_from(proj_idx).unwrap_or(-1)
                    && creature_idx < state.creatures.len()
                {
                    let links_left = state.shock_chain_links_left;
                    if links_left > 0 && !state.creatures.is_empty() {
                        state.shock_chain_links_left = links_left - 1;

                        let origin_pos = state.projectiles[proj_idx].pos;
                        let mut best_idx = 0_usize;
                        let mut best_dist_sq = 1.0e12_f64;
                        let min_dist_sq = 100.0_f64 * 100.0_f64;
                        for candidate_idx in 0..state.creatures.len() {
                            if candidate_idx == creature_idx {
                                continue;
                            }
                            if !state.creatures[candidate_idx].active {
                                continue;
                            }
                            let dx = f64::from(state.creatures[candidate_idx].pos.x)
                                - f64::from(origin_pos.x);
                            let dy = f64::from(state.creatures[candidate_idx].pos.y)
                                - f64::from(origin_pos.y);
                            let d_sq = dx * dx + dy * dy;
                            if d_sq <= min_dist_sq {
                                continue;
                            }
                            if d_sq < best_dist_sq {
                                best_dist_sq = d_sq;
                                best_idx = candidate_idx;
                            }
                        }

                        let origin = state.creatures[creature_idx].pos;
                        let target = state.creatures[best_idx].pos;
                        let angle = (f64::from(target.y) - f64::from(origin.y))
                            .atan2(f64::from(target.x) - f64::from(origin.x))
                            + std::f64::consts::FRAC_PI_2;
                        if std::env::var("CRIMSON_RUST_DEBUG_SHOCK").is_ok() {
                            eprintln!(
                                "dbg shock_chain tick={} proj={} hit_idx={} origin_hit=({}, {}) origin_creature=({}, {}) best_idx={} target=({}, {}) angle={}",
                                state.debug_tick_index,
                                proj_idx,
                                creature_idx,
                                origin_pos.x,
                                origin_pos.y,
                                origin.x,
                                origin.y,
                                best_idx,
                                target.x,
                                target.y,
                                angle
                            );
                        }

                        let prev_guard = state.bonus_spawn_guard;
                        state.bonus_spawn_guard = true;
                        if let Some(next_proj_idx) = spawn_bonus_projectile(
                            state,
                            origin_pos,
                            angle,
                            type_id,
                            None,
                            i64::try_from(creature_idx).unwrap_or(-1),
                        ) {
                            state.shock_chain_projectile_id =
                                i32::try_from(next_proj_idx).unwrap_or(-1);
                        }
                        state.bonus_spawn_guard = prev_guard;
                    }
                }
                consume_projectile_ion_hit_effect_rng(state, type_id);
                let damage_scale = projectile_damage_scale_for_type(type_id);
                let damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95;
                let projectile_impulse_axis =
                    ((state.projectiles[proj_idx].angle as f32 - NATIVE_HALF_PI).cos()
                        * state.projectiles[proj_idx].speed_scale) as f32;
                let projectile_impulse = Vec2f {
                    x: projectile_impulse_axis,
                    y: projectile_impulse_axis,
                };

                if damage_amount > 0.0
                    && creature_idx < state.creatures.len()
                    && state.creatures[creature_idx].active
                    && state.creatures[creature_idx].health > 0.0
                {
                    if (state.creatures[creature_idx].flags & CREATURE_FLAG_ANIM_PING_PONG) == 0 {
                        let jitter = ((state.rng.rand() & 0x7F) as i32 - 0x40) as f32 * 0.002;
                        let size = state.creatures[creature_idx].size.max(1e-6);
                        let mut turn = jitter / (size * 0.025);
                        if turn > std::f32::consts::PI * 0.5 {
                            turn = std::f32::consts::PI * 0.5;
                        }
                        state.creatures[creature_idx].heading += f64::from(turn);
                    }

                    let remaining = state.projectiles[proj_idx].damage_pool - 1.0;
                    state.projectiles[proj_idx].damage_pool = remaining;
                    if remaining <= 0.0 {
                        let mut reward_value = None;
                        let mut death_pos = None;
                        let mut death_sfx_draw = false;
                        let scaled_damage_amount =
                            apply_bullet_damage_perk_scale(state, damage_amount);
                        {
                            let creature = &mut state.creatures[creature_idx];
                            if creature.active && creature.health > 0.0 {
                                creature.vel = creature.vel.sub(projectile_impulse);
                                creature.health -= scaled_damage_amount;
                                if creature.health <= 0.0
                                    && creature.lifecycle_stage == CREATURE_LIFECYCLE_ALIVE
                                {
                                    creature.lifecycle_stage = if dt_s > 0.0 {
                                        // Native death transition decrements hitbox in both
                                        // `creature_apply_damage` and subsequent `creature_handle_death`.
                                        let first = (f64::from(creature.lifecycle_stage)
                                            - f64::from(dt_s))
                                            as f32;
                                        (f64::from(first) - f64::from(dt_s)) as f32
                                    } else {
                                        (f64::from(creature.lifecycle_stage) - 0.001_f64) as f32
                                    };
                                    creature.vel = creature.vel.sub(projectile_impulse.scale(2.0));
                                    reward_value = Some(creature.reward_value);
                                    death_pos = Some(creature.pos);
                                    death_sfx_draw =
                                        (creature.flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) == 0;
                                }
                            }
                        }
                        if let Some(reward) = reward_value {
                            let _ = award_player_xp_from_creature_reward(state, reward);
                            if let Some(pos) = death_pos {
                                let draws_before = state.rng.draw_count();
                                let spawned = bonus_try_spawn_on_kill(state, pos);
                                if spawned {
                                    consume_spawn_burst_rng(&mut state.rng, 16);
                                }
                                let draws_after = state.rng.draw_count();
                                let delta = draws_after.saturating_sub(draws_before);
                                state.debug_bonus_flow_draws_tick = state
                                    .debug_bonus_flow_draws_tick
                                    .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));
                            }
                            if death_sfx_draw {
                                consume_death_sfx_draw_if_planned(state);
                            }
                            apply_freeze_kill_cleanup(state, creature_idx);
                        }
                        if state.projectiles[proj_idx].life_timer != 0.25 {
                            state.projectiles[proj_idx].life_timer = 0.25;
                        }
                    } else {
                        let mut creature_hp_after = 0.0;
                        let mut reward_value = None;
                        let mut death_pos = None;
                        let mut death_sfx_draw = false;
                        let scaled_remaining = apply_bullet_damage_perk_scale(state, remaining);
                        {
                            let creature = &mut state.creatures[creature_idx];
                            if creature.active && creature.health > 0.0 {
                                creature.vel = creature.vel.sub(projectile_impulse);
                                creature.health -= scaled_remaining;
                                creature_hp_after = creature.health;
                                if creature.health <= 0.0
                                    && creature.lifecycle_stage == CREATURE_LIFECYCLE_ALIVE
                                {
                                    creature.lifecycle_stage = if dt_s > 0.0 {
                                        // Native death transition decrements hitbox in both
                                        // `creature_apply_damage` and subsequent `creature_handle_death`.
                                        let first = (f64::from(creature.lifecycle_stage)
                                            - f64::from(dt_s))
                                            as f32;
                                        (f64::from(first) - f64::from(dt_s)) as f32
                                    } else {
                                        (f64::from(creature.lifecycle_stage) - 0.001_f64) as f32
                                    };
                                    creature.vel = creature.vel.sub(projectile_impulse.scale(2.0));
                                    reward_value = Some(creature.reward_value);
                                    death_pos = Some(creature.pos);
                                    death_sfx_draw =
                                        (creature.flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) == 0;
                                }
                            }
                        }
                        state.projectiles[proj_idx].damage_pool -= creature_hp_after;
                        if let Some(reward) = reward_value {
                            let _ = award_player_xp_from_creature_reward(state, reward);
                            if let Some(pos) = death_pos {
                                let draws_before = state.rng.draw_count();
                                let spawned = bonus_try_spawn_on_kill(state, pos);
                                if spawned {
                                    consume_spawn_burst_rng(&mut state.rng, 16);
                                }
                                let draws_after = state.rng.draw_count();
                                let delta = draws_after.saturating_sub(draws_before);
                                state.debug_bonus_flow_draws_tick = state
                                    .debug_bonus_flow_draws_tick
                                    .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));
                            }
                            if death_sfx_draw {
                                consume_death_sfx_draw_if_planned(state);
                            }
                            apply_freeze_kill_cleanup(state, creature_idx);
                        }
                    }
                }

                consume_projectile_hit_post_rng(
                    &mut state.rng,
                    type_id,
                    state.bonuses.freeze > 0.0,
                );
                consume_projectile_hit_sfx_rng(state, type_id);

                if state.projectiles[proj_idx].damage_pool == 1.0 {
                    let life_before = state.projectiles[proj_idx].life_timer;
                    state.projectiles[proj_idx].damage_pool = 0.0;
                    if life_before != 0.25 {
                        state.projectiles[proj_idx].life_timer = 0.25;
                    }
                }

                let should_break = {
                    let proj = &state.projectiles[proj_idx];
                    (proj.life_timer == 0.25 && !projectile_is_piercing_type(proj.type_id))
                        || proj.damage_pool <= 0.0
                };
                if should_break {
                    break;
                }
            }

            step += 3;
        }
    }
}

fn runtime_creature_hit_radius(size: f32) -> f32 {
    size.max(0.0) * 0.142_857_15 + 3.0
}

fn runtime_within_native_find_radius(
    origin: Vec2f,
    target: Vec2f,
    radius: f32,
    target_size: f32,
) -> bool {
    // Python parity path keeps this predicate in f64 arithmetic.
    let dx = f64::from(target.x) - f64::from(origin.x);
    let dy = f64::from(target.y) - f64::from(origin.y);
    let radius_f = f64::from(radius);
    let size_margin = f64::from(target_size) * 0.142_857_15_f64 + 3.0_f64;
    let max_axis_delta = radius_f + size_margin;
    if dx.abs() > max_axis_delta || dy.abs() > max_axis_delta {
        return false;
    }
    let margin = (dx * dx + dy * dy).sqrt() - radius_f - size_margin;
    margin < 0.0_f64
}

fn award_experience_once_from_reward(player: &mut PlayerState, reward_value: f32) -> i64 {
    let reward_f32 = reward_value as f32;
    if reward_f32 <= 0.0 || !reward_f32.is_finite() {
        return 0;
    }
    let before = player.experience;
    let total_f32 = ((before as f32) + reward_f32) as f32;
    let after = total_f32 as i64;
    player.experience = after;
    after - before
}

fn award_player_xp_from_creature_reward(state: &mut SimState, reward_value: f32) -> i64 {
    let gained = award_experience_once_from_reward(&mut state.player, reward_value);
    if gained <= 0 {
        return 0;
    }
    if state.bonuses.double_experience > 0.0 {
        return gained + award_experience_once_from_reward(&mut state.player, reward_value);
    }
    gained
}

fn survival_progression_update(state: &mut SimState) {
    let threshold = survival_level_threshold(state.player.level);
    if state.player.experience > threshold {
        state.player.level += 1;
        state.perk_selection.pending_count += 1;
        state.perk_selection.choices_dirty = true;
    }
}

fn survival_level_threshold(level: i64) -> i64 {
    let level = level.max(1) as f64;
    (1000.0 + level.powf(1.8) * 1000.0) as i64
}

fn perk_selection_current_choices(state: &mut SimState) -> Vec<usize> {
    if state.perk_selection.choices_dirty || state.perk_selection.choices.is_empty() {
        state.perk_selection.choices = perk_generate_choices(state);
        state.perk_selection.choices_dirty = false;
    }

    let visible_count = perk_choice_count(&state.player);
    state
        .perk_selection
        .choices
        .iter()
        .take(visible_count)
        .map(|value| usize::try_from(*value).unwrap_or(0))
        .collect()
}

fn perk_choice_count(player: &PlayerState) -> usize {
    if perk_active(player, PERK_PERK_MASTER) {
        return 7;
    }
    if perk_active(player, PERK_PERK_EXPERT) {
        return 6;
    }
    5
}

fn perk_selection_pick(state: &mut SimState, choice_index: i64) -> Option<usize> {
    if state.perk_selection.pending_count <= 0 {
        return None;
    }
    let choices = perk_selection_current_choices(state);
    if choices.is_empty() {
        return None;
    }
    let idx = usize::try_from(choice_index).ok()?;
    if idx >= choices.len() {
        return None;
    }

    let perk_id = choices[idx];
    perk_apply(state, perk_id);
    state.perk_selection.pending_count = (state.perk_selection.pending_count - 1).max(0);
    state.perk_selection.choices_dirty = true;
    Some(perk_id)
}

fn perk_generate_choices(state: &mut SimState) -> Vec<i16> {
    let offerable_mask = perk_offerable_mask(state);
    let death_clock_active = perk_active(&state.player, PERK_DEATH_CLOCK);
    let pyromaniac_allowed = state.player.weapon_id == WEAPON_FLAMETHROWER;

    let mut choices: Vec<i16> = vec![PERK_ANTIPERK as i16; 7];
    let mut choice_index = 0_usize;

    while choice_index < 7 {
        let mut attempts = 0_i32;
        let picked = loop {
            attempts += 1;
            let perk_id = select_random_offer(state, &offerable_mask);

            if perk_id == PERK_PYROMANIAC && !pyromaniac_allowed {
                continue;
            }
            if death_clock_active && contains_id(DEATH_CLOCK_BLOCKED, perk_id as i16) {
                continue;
            }
            if contains_id(PERK_RARITY_GATE, perk_id as i16) && ((state.rng.rand() & 3) == 1) {
                continue;
            }

            let flags = perk_flags(perk_id);
            let stackable = (flags & PERK_FLAGS_STACKABLE) != 0;

            if attempts > 10_000 && stackable {
                break perk_id;
            }
            if choices
                .iter()
                .take(choice_index)
                .any(|entry| *entry == perk_id as i16)
            {
                continue;
            }
            if stackable || state.player.perk_counts[perk_id] < 1 || attempts > 29_999 {
                break perk_id;
            }
        };
        choices[choice_index] = picked as i16;
        choice_index += 1;
    }

    choices
}

fn select_random_offer(state: &mut SimState, offerable_mask: &[bool; PERK_COUNT_SIZE]) -> usize {
    for _ in 0..1000 {
        let perk_id = usize::try_from(state.rng.rand()).unwrap_or(0) % PERK_ID_MAX + 1;
        if perk_id < offerable_mask.len() && offerable_mask[perk_id] {
            return perk_id;
        }
    }
    PERK_INSTANT_WINNER
}

fn perk_offerable_mask(state: &mut SimState) -> [bool; PERK_COUNT_SIZE] {
    perks_rebuild_available(state);
    let mut offerable = [false; PERK_COUNT_SIZE];
    let max_index = PERK_ID_MAX.min(PERK_COUNT_SIZE - 1);
    for perk_id in 1..=max_index {
        if !state.perk_available[perk_id] {
            continue;
        }
        if perk_can_offer(state, perk_id) {
            offerable[perk_id] = true;
        }
    }
    offerable
}

fn perk_can_offer(state: &SimState, perk_id: usize) -> bool {
    if perk_id == PERK_ANTIPERK {
        return false;
    }

    let Some(spec) = perk_spec(perk_id) else {
        return false;
    };

    if state.game_mode == GAME_MODE_QUESTS
        && state.hardcore
        && state.quest_stage_major == 2
        && state.quest_stage_minor == 10
        && (perk_id == 25 || perk_id == 36 || perk_id == 10)
    {
        return false;
    }

    if state.game_mode == GAME_MODE_QUESTS && (spec.flags & PERK_FLAGS_QUEST_ALLOWED) == 0 {
        return false;
    }
    if state.player_count == 2 && (spec.flags & PERK_FLAGS_TWO_PLAYER_ALLOWED) == 0 {
        return false;
    }

    let prereq = usize::try_from(spec.prereq_perk_id).unwrap_or(0);
    if prereq > 0
        && prereq < state.player.perk_counts.len()
        && state.player.perk_counts[prereq] <= 0
    {
        return false;
    }

    true
}

fn perks_rebuild_available(state: &mut SimState) {
    if state.perk_available_unlock_index == state.quest_unlock_index {
        return;
    }

    state.perk_available.fill(false);

    let base_max = usize::try_from(PERK_BASE_AVAILABLE_MAX_ID).unwrap_or(0);
    for perk_id in 1..=base_max.min(PERK_COUNT_SIZE - 1) {
        state.perk_available[perk_id] = true;
    }

    for perk_id in PERK_ALWAYS_AVAILABLE {
        let idx = usize::try_from(*perk_id).unwrap_or(0);
        if idx < state.perk_available.len() {
            state.perk_available[idx] = true;
        }
    }

    let unlock_count = usize::try_from(state.quest_unlock_index.max(0)).unwrap_or(0);
    for perk_id in QUEST_UNLOCK_PERK_IDS.iter().take(unlock_count) {
        let idx = usize::try_from((*perk_id).max(0)).unwrap_or(0);
        if idx > 0 && idx < state.perk_available.len() {
            state.perk_available[idx] = true;
        }
    }

    state.perk_available[PERK_ANTIPERK] = false;
    state.perk_available_unlock_index = state.quest_unlock_index;
}

fn perk_apply(state: &mut SimState, perk_id: usize) {
    if perk_id < state.player.perk_counts.len() {
        state.player.perk_counts[perk_id] += 1;
    }

    match perk_id {
        PERK_INSTANT_WINNER => {
            state.player.experience += 2500;
        }
        PERK_AMMO_MANIAC => {
            let current = state.player.weapon_id;
            weapon_assign_player(state, current);
        }
        PERK_MY_FAVOURITE_WEAPON => {
            state.player.clip_size += 2;
        }
        PERK_INFERNAL_CONTRACT => {
            state.player.level += 3;
            state.perk_selection.pending_count += 3;
            state.perk_selection.choices_dirty = true;
            if state.player.health > 0.0 {
                state.player.health = 0.1;
            }
        }
        PERK_FATAL_LOTTERY => {
            if (state.rng.rand() & 1) != 0 {
                state.player.health = -1.0;
            } else {
                state.player.experience += 10_000;
            }
        }
        PERK_RANDOM_WEAPON => {
            let current = state.player.weapon_id;
            let mut picked = current;
            for _ in 0..100 {
                let candidate = weapon_pick_random_available(state);
                picked = candidate;
                if candidate != WEAPON_PISTOL && candidate != current {
                    break;
                }
            }
            weapon_assign_player(state, picked);
        }
        PERK_GRIM_DEAL => {
            state.player.health = -1.0;
            state.player.experience += ((state.player.experience as f32) * 0.18) as i64;
        }
        PERK_BANDAGE => {
            if state.player.health > 0.0 {
                let amount = (state.rng.rand() % 50 + 1) as f32;
                if state.preserve_bugs {
                    state.player.health = (state.player.health * amount).min(100.0);
                } else {
                    state.player.health = (state.player.health + amount).min(100.0);
                }
            }
        }
        PERK_THICK_SKINNED => {
            if state.player.health > 0.0 {
                state.player.health = (state.player.health * (2.0 / 3.0)).max(1.0);
            }
        }
        PERK_BREATHING_ROOM => {
            state.player.health -= state.player.health * (2.0 / 3.0);
        }
        PERK_LIFELINE_50_50 => {
            // Creature-side apply path not ported yet.
        }
        _ => {}
    }
}

fn weapon_pick_random_available(state: &mut SimState) -> i64 {
    weapon_refresh_available(state);
    let draws_before = state.rng.draw_count();
    let debug_pick = std::env::var_os("CRIMSON_RUST_DEBUG_WEAPON_PICK").is_some();

    for iter in 0..1000 {
        let base_rand = state.rng.rand();
        let mut weapon_id = i64::from(base_rand % WEAPON_DROP_ID_COUNT + 1);

        let usage_idx = usize::try_from(weapon_id.max(0)).unwrap_or(0);
        let mut reroll_gate = None;
        let mut reroll_rand = None;
        if usage_idx < state.status_weapon_usage_counts.len()
            && state.status_weapon_usage_counts[usage_idx] != 0
        {
            let gate_rand = state.rng.rand();
            reroll_gate = Some(gate_rand);
            if (gate_rand & 1) == 0 {
                let rr = state.rng.rand();
                reroll_rand = Some(rr);
                weapon_id = i64::from(rr % WEAPON_DROP_ID_COUNT + 1);
            }
        }

        let idx = usize::try_from(weapon_id.max(0)).unwrap_or(0);
        if idx < state.weapon_available.len() && state.weapon_available[idx] {
            if debug_pick {
                eprintln!(
                    "weapon_pick iter={iter} base_rand={base_rand} usage={} gate={:?} reroll={:?} weapon_id={weapon_id} accepted=1",
                    if usage_idx < state.status_weapon_usage_counts.len() {
                        state.status_weapon_usage_counts[usage_idx]
                    } else {
                        -1
                    },
                    reroll_gate,
                    reroll_rand,
                );
            }
            let draws_after = state.rng.draw_count();
            let delta = draws_after.saturating_sub(draws_before);
            state.debug_weapon_pick_draws_tick = state
                .debug_weapon_pick_draws_tick
                .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));
            return weapon_id;
        }
        if debug_pick {
            eprintln!(
                "weapon_pick iter={iter} base_rand={base_rand} usage={} gate={:?} reroll={:?} weapon_id={weapon_id} accepted=0",
                if usage_idx < state.status_weapon_usage_counts.len() {
                    state.status_weapon_usage_counts[usage_idx]
                } else {
                    -1
                },
                reroll_gate,
                reroll_rand,
            );
        }
    }

    let draws_after = state.rng.draw_count();
    let delta = draws_after.saturating_sub(draws_before);
    state.debug_weapon_pick_draws_tick = state
        .debug_weapon_pick_draws_tick
        .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));
    WEAPON_PISTOL
}

fn weapon_refresh_available(state: &mut SimState) {
    if state.weapon_available_game_mode == state.game_mode
        && state.weapon_available_unlock_index == state.quest_unlock_index
        && state.weapon_available_unlock_index_full == state.quest_unlock_index_full
    {
        return;
    }

    state.weapon_available.fill(false);

    let pistol_idx = usize::try_from(WEAPON_PISTOL).unwrap_or(0);
    if pistol_idx < state.weapon_available.len() {
        state.weapon_available[pistol_idx] = true;
    }

    let unlock_count = usize::try_from(state.quest_unlock_index.max(0)).unwrap_or(0);
    for weapon_id in QUEST_UNLOCK_WEAPON_IDS.iter().take(unlock_count) {
        let idx = usize::try_from((*weapon_id).max(0)).unwrap_or(0);
        if idx > 0 && idx < state.weapon_available.len() {
            state.weapon_available[idx] = true;
        }
    }

    if state.game_mode == GAME_MODE_SURVIVAL {
        for weapon_id in [WEAPON_ASSAULT_RIFLE, WEAPON_SHOTGUN, WEAPON_SUBMACHINE_GUN] {
            let idx = usize::try_from(weapon_id).unwrap_or(0);
            if idx < state.weapon_available.len() {
                state.weapon_available[idx] = true;
            }
        }
    }

    if !state.preserve_bugs && state.quest_unlock_index_full >= 0x28 {
        let idx = usize::try_from(29_i64).unwrap_or(0);
        if idx < state.weapon_available.len() {
            state.weapon_available[idx] = true;
        }
    }

    state.weapon_available_game_mode = state.game_mode;
    state.weapon_available_unlock_index = state.quest_unlock_index;
    state.weapon_available_unlock_index_full = state.quest_unlock_index_full;
}

fn weapon_spec(weapon_id: i64) -> Option<&'static crate::tables::WeaponSpec> {
    WEAPON_SPECS
        .iter()
        .find(|entry| i64::from(entry.weapon_id) == weapon_id)
}

fn perk_spec(perk_id: usize) -> Option<&'static crate::tables::PerkSpec> {
    PERK_SPECS
        .iter()
        .find(|entry| usize::try_from(entry.perk_id).ok() == Some(perk_id))
}

fn perk_flags(perk_id: usize) -> u8 {
    perk_spec(perk_id).map_or(0, |entry| entry.flags)
}

fn perk_active(player: &PlayerState, perk_id: usize) -> bool {
    perk_id < player.perk_counts.len() && player.perk_counts[perk_id] > 0
}

fn contains_id(values: &[i16], id: i16) -> bool {
    values.contains(&id)
}

fn unpack_input_flags(flags: i64) -> ReplayInputFlags {
    let move_keys_present = (flags & MOVE_KEYS_PRESENT_FLAG) != 0;
    let move_mode = if (flags & MOVE_MODE_PRESENT_FLAG) != 0 {
        Some((flags >> MOVE_MODE_SHIFT) & MOVE_MODE_MASK)
    } else {
        None
    };
    let aim_scheme = if (flags & AIM_SCHEME_PRESENT_FLAG) != 0 {
        let raw = (flags >> AIM_SCHEME_SHIFT) & AIM_SCHEME_MASK;
        if raw == AIM_SCHEME_MASK {
            Some(AIM_SCHEME_UNKNOWN)
        } else {
            Some(raw)
        }
    } else {
        None
    };

    ReplayInputFlags {
        fire_down: (flags & FIRE_DOWN_FLAG) != 0,
        fire_pressed: (flags & FIRE_PRESSED_FLAG) != 0,
        reload_pressed: (flags & RELOAD_PRESSED_FLAG) != 0,
        move_mode,
        aim_scheme,
        move_forward_pressed: if move_keys_present {
            Some((flags & MOVE_FORWARD_FLAG) != 0)
        } else {
            None
        },
        move_backward_pressed: if move_keys_present {
            Some((flags & MOVE_BACKWARD_FLAG) != 0)
        } else {
            None
        },
        turn_left_pressed: if move_keys_present {
            Some((flags & TURN_LEFT_FLAG) != 0)
        } else {
            None
        },
        turn_right_pressed: if move_keys_present {
            Some((flags & TURN_RIGHT_FLAG) != 0)
        } else {
            None
        },
    }
}

fn most_used_weapon_id(fallback_weapon_id: i64, shot_counts_by_weapon: &[i64]) -> i64 {
    if shot_counts_by_weapon.len() <= 1 {
        return fallback_weapon_id;
    }

    let mut best_idx: usize = 1;
    let mut best_count: i64 = 0;
    for (idx, count) in shot_counts_by_weapon.iter().enumerate().skip(1) {
        if *count > best_count {
            best_count = *count;
            best_idx = idx;
        }
    }

    if best_count > 0 {
        return i64::try_from(best_idx).unwrap_or(fallback_weapon_id);
    }
    fallback_weapon_id
}

fn resolve_score_metric(game_mode_id: i64, score_metric: ScoreMetric) -> &'static str {
    match score_metric {
        ScoreMetric::ScoreXp => "score_xp",
        ScoreMetric::ElapsedMs => "elapsed_ms",
        ScoreMetric::Auto => {
            if game_mode_id == 2 || game_mode_id == 3 {
                "elapsed_ms"
            } else {
                "score_xp"
            }
        }
    }
}

fn terrain_edge_from_world_size(world_size: f64) -> Result<i32, VerifyError> {
    if !world_size.is_finite() {
        return Err(VerifyError::UnsupportedScope(format!(
            "invalid world_size={} (must be finite)",
            world_size
        )));
    }
    let edge = world_size.trunc() as i64;
    if edge <= 0 || edge > i64::from(i32::MAX) {
        return Err(VerifyError::UnsupportedScope(format!(
            "invalid world_size={} (must truncate into positive i32)",
            world_size
        )));
    }
    Ok(edge as i32)
}

fn open_trace_writer() -> Result<Option<BufWriter<fs::File>>, VerifyError> {
    let Some(path) = std::env::var_os("CRIMSON_RUST_TRACE_JSONL") else {
        return Ok(None);
    };
    let file = fs::File::create(path)?;
    Ok(Some(BufWriter::new(file)))
}

fn max_ticks_override_from_env() -> Option<usize> {
    let raw = std::env::var("CRIMSON_RUST_MAX_TICKS").ok()?;
    raw.parse::<usize>().ok()
}

fn round4(value: f32) -> f32 {
    (value * 10_000.0).round() / 10_000.0
}

fn bonus_timer_ms(value: f32) -> i64 {
    let ms = (f64::from(value) * 1000.0).round() as i64;
    ms.max(0)
}

fn trace_target_offset(creature: &RuntimeCreature) -> serde_json::Value {
    if creature.target_offset.x != 0.0 || creature.target_offset.y != 0.0 {
        serde_json::json!({
            "x": round4(creature.target_offset.x),
            "y": round4(creature.target_offset.y),
        })
    } else {
        serde_json::Value::Null
    }
}

fn write_trace_row(
    writer: &mut BufWriter<fs::File>,
    tick_index: i64,
    state: &SimState,
    elapsed_ms: f64,
) -> Result<(), VerifyError> {
    let bonus_count = state
        .bonus_pool
        .iter()
        .filter(|entry| entry.bonus_id != BONUS_ID_UNUSED)
        .count() as i64;
    let first_bonus = state
        .bonus_pool
        .iter()
        .find(|entry| entry.bonus_id != BONUS_ID_UNUSED)
        .map_or(serde_json::Value::Null, |entry| {
            serde_json::json!({
                "bonus_id": entry.bonus_id,
                "amount": entry.amount,
                "picked": entry.picked,
                "time_left": round4(entry.time_left),
                "pos": {
                    "x": round4(entry.pos.x),
                    "y": round4(entry.pos.y),
                },
            })
        });
    let bonus_slots_head: Vec<serde_json::Value> = state
        .bonus_pool
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.bonus_id != BONUS_ID_UNUSED)
        .map(|(idx, entry)| {
            serde_json::json!({
                "index": i64::try_from(idx).unwrap_or(i64::MAX),
                "bonus_id": entry.bonus_id,
                "amount": entry.amount,
                "picked": entry.picked,
                "time_left": round4(entry.time_left),
                "time_max": round4(entry.time_max),
                "pos": {
                    "x": round4(entry.pos.x),
                    "y": round4(entry.pos.y),
                },
            })
        })
        .collect();
    let first_creature = state.creatures.iter().find(|entry| entry.active).map_or(
        serde_json::Value::Null,
        |creature| {
            serde_json::json!({
                "pos": {
                    "x": round4(creature.pos.x),
                    "y": round4(creature.pos.y),
                },
                "type_id": creature.type_id,
                "hp": round4(creature.health),
                "lifecycle_stage": round4(creature.lifecycle_stage),
                "heading": round4(creature.heading as f32),
                "target_heading": round4(creature.target_heading as f32),
                "ai_mode": creature.ai_mode,
                "link_index": creature.link_index,
                "flags": creature.flags,
                "attack_cooldown": round4(creature.attack_cooldown),
                "move_speed": round4(creature.move_speed),
                "move_scale": round4(creature.move_scale),
                "size": round4(creature.size),
                "max_health": round4(creature.max_health),
                "contact_damage": round4(creature.contact_damage),
                "vel": {
                    "x": round4(creature.vel.x),
                    "y": round4(creature.vel.y),
                },
                "force_target": creature.force_target,
                "target": {
                    "x": round4(creature.target.x),
                    "y": round4(creature.target.y),
                },
                "phase_seed": round4(creature.phase_seed),
                "target_offset": trace_target_offset(creature),
            })
        },
    );
    let creature_slots_head: Vec<serde_json::Value> = state
        .creatures
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.active)
        .take(64)
        .map(|(idx, creature)| {
            serde_json::json!({
                "index": i64::try_from(idx).unwrap_or(i64::MAX),
                "type_id": creature.type_id,
                "hp": round4(creature.health),
                "lifecycle_stage": round4(creature.lifecycle_stage),
                "heading": round4(creature.heading as f32),
                "target_heading": round4(creature.target_heading as f32),
                "ai_mode": creature.ai_mode,
                "link_index": creature.link_index,
                "flags": creature.flags,
                "attack_cooldown": round4(creature.attack_cooldown),
                "move_speed": round4(creature.move_speed),
                "move_scale": round4(creature.move_scale),
                "size": round4(creature.size),
                "max_health": round4(creature.max_health),
                "contact_damage": round4(creature.contact_damage),
                "vel": {
                    "x": round4(creature.vel.x),
                    "y": round4(creature.vel.y),
                },
                "force_target": creature.force_target,
                "target": {
                    "x": round4(creature.target.x),
                    "y": round4(creature.target.y),
                },
                "phase_seed": round4(creature.phase_seed),
                "target_offset": trace_target_offset(creature),
                "pos": {
                    "x": round4(creature.pos.x),
                    "y": round4(creature.pos.y),
                },
            })
        })
        .collect();
    let projectile_count = state
        .projectiles
        .iter()
        .filter(|entry| entry.active)
        .count() as i64;
    let projectiles_head: Vec<serde_json::Value> = state
        .projectiles
        .iter()
        .filter(|entry| entry.active)
        .take(8)
        .map(|proj| {
            serde_json::json!({
                "type_id": proj.type_id,
                "angle": round4(proj.angle as f32),
                "speed_scale": round4(proj.speed_scale as f32),
                "life_timer": round4(proj.life_timer),
                "damage_pool": round4(proj.damage_pool),
                "pos": {
                    "x": round4(proj.pos.x),
                    "y": round4(proj.pos.y),
                },
            })
        })
        .collect();
    let projectile_slots_head: Vec<serde_json::Value> = state
        .projectiles
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.active)
        .take(64)
        .map(|(idx, proj)| {
            serde_json::json!({
                "index": i64::try_from(idx).unwrap_or(i64::MAX),
                "type_id": proj.type_id,
                "owner_id": proj.owner_id,
                "angle": round4(proj.angle as f32),
                "speed_scale": round4(proj.speed_scale as f32),
                "life_timer": round4(proj.life_timer),
                "damage_pool": round4(proj.damage_pool),
                "pos": {
                    "x": round4(proj.pos.x),
                    "y": round4(proj.pos.y),
                },
            })
        })
        .collect();
    let first_projectile_entry = state.projectiles.iter().find(|entry| entry.active);
    let first_projectile = first_projectile_entry.map_or(serde_json::Value::Null, |proj| {
        serde_json::json!({
            "pos": {
                "x": round4(proj.pos.x),
                "y": round4(proj.pos.y),
            },
            "type_id": proj.type_id,
            "angle": round4(proj.angle as f32),
            "life_timer": round4(proj.life_timer),
            "damage_pool": round4(proj.damage_pool),
        })
    });
    let first_projectile_raw = first_projectile_entry.map_or(serde_json::Value::Null, |proj| {
        serde_json::json!({
            "pos": {
                "x": f64::from(proj.pos.x),
                "y": f64::from(proj.pos.y),
            },
            "type_id": proj.type_id,
            "angle": proj.angle,
            "life_timer": f64::from(proj.life_timer),
            "damage_pool": f64::from(proj.damage_pool),
        })
    });
    let first_projectile_nearest_creature =
        first_projectile_entry.map_or(serde_json::Value::Null, |proj| {
            let mut best: Option<(f32, &RuntimeCreature)> = None;
            for creature in state.creatures.iter().filter(|entry| entry.active) {
                let dx = creature.pos.x - proj.pos.x;
                let dy = creature.pos.y - proj.pos.y;
                let dist_sq = dx * dx + dy * dy;
                match best {
                    Some((best_dist_sq, _)) if dist_sq >= best_dist_sq => {}
                    _ => {
                        best = Some((dist_sq, creature));
                    }
                }
            }
            best.map_or(serde_json::Value::Null, |(dist_sq, creature)| {
                serde_json::json!({
                    "distance": round4(dist_sq.sqrt()),
                    "type_id": creature.type_id,
                    "hp": round4(creature.health),
                    "lifecycle_stage": round4(creature.lifecycle_stage),
                    "pos": {
                        "x": round4(creature.pos.x),
                        "y": round4(creature.pos.y),
                    },
                })
            })
        });
    let debug_projectile_hits_detail_tick: Vec<serde_json::Value> = state
        .debug_projectile_hits_detail_tick
        .iter()
        .map(|entry| {
            serde_json::json!({
                "projectile_index": i64::try_from(entry.projectile_index).unwrap_or(i64::MAX),
                "creature_index": i64::try_from(entry.creature_index).unwrap_or(i64::MAX),
                "type_id": entry.type_id,
                "hit_pos": {
                    "x": round4(entry.hit_pos.x),
                    "y": round4(entry.hit_pos.y),
                },
                "target_pos": {
                    "x": round4(entry.target_pos.x),
                    "y": round4(entry.target_pos.y),
                },
                "target_size": round4(entry.target_size),
            })
        })
        .collect();
    let row = serde_json::json!({
        "tick_index": tick_index,
        "rng_state": state.rng.state(),
        "rng_draw_count": state.rng.draw_count(),
        "debug_dt_world_tick": round4(state.debug_dt_world_tick),
        "elapsed_ms": elapsed_ms.round() as i64,
        "score_xp": state.player.experience,
        "kills": state.creature_kill_count,
        "creature_count": state.creatures.iter().filter(|entry| entry.active).count() as i64,
        "perk_pending": state.perk_selection.pending_count,
        "player0": {
            "pos": {
                "x": round4(state.player_pos.x),
                "y": round4(state.player_pos.y),
            },
            "heading": round4(state.player.heading),
            "turn_speed": round4(state.player.turn_speed),
            "aim_heading": round4(state.player.aim_heading),
            "health": round4(state.player.health),
            "weapon_id": state.player.weapon_id,
            "ammo": round4(state.player.ammo),
            "experience": state.player.experience,
            "level": state.player.level,
            "spread_heat": round4(state.player.spread_heat as f32),
            "shot_cooldown": round4(state.player.shot_cooldown),
            "reload_timer": round4(state.player.reload_timer),
        },
        "player0_raw": {
            "pos": {
                "x": f64::from(state.player_pos.x),
                "y": f64::from(state.player_pos.y),
            },
            "heading": f64::from(state.player.heading),
            "turn_speed": f64::from(state.player.turn_speed),
            "aim_heading": f64::from(state.player.aim_heading),
            "health": f64::from(state.player.health),
            "weapon_id": state.player.weapon_id,
            "ammo": f64::from(state.player.ammo),
            "experience": state.player.experience,
            "level": state.player.level,
            "spread_heat": state.player.spread_heat,
            "shot_cooldown": f64::from(state.player.shot_cooldown),
            "reload_timer": f64::from(state.player.reload_timer),
        },
        "bonus_timers": {
            "4": bonus_timer_ms(state.bonuses.weapon_power_up),
            "9": bonus_timer_ms(state.bonuses.reflex_boost),
            "2": bonus_timer_ms(state.bonuses.energizer),
            "6": bonus_timer_ms(state.bonuses.double_experience),
            "11": bonus_timer_ms(state.bonuses.freeze),
        },
        "bonus_timers_raw": {
            "4": f64::from(state.bonuses.weapon_power_up),
            "9": f64::from(state.bonuses.reflex_boost),
            "2": f64::from(state.bonuses.energizer),
            "6": f64::from(state.bonuses.double_experience),
            "11": f64::from(state.bonuses.freeze),
        },
        "projectile_count": projectile_count,
        "projectile_pool_len": i64::try_from(state.projectiles.len()).unwrap_or(i64::MAX),
        "first_projectile": first_projectile,
        "first_projectile_raw": first_projectile_raw,
        "projectiles_head": projectiles_head,
        "projectile_slots_head": projectile_slots_head,
        "first_creature": first_creature,
        "creature_slots_head": creature_slots_head,
        "first_projectile_nearest_creature": first_projectile_nearest_creature,
        "bonus_count": bonus_count,
        "first_bonus": first_bonus,
        "bonus_slots_head": bonus_slots_head,
        "shots_fired": state.shots_fired,
        "shots_hit": state.shots_hit,
        "weapon_shots_fired": state.weapon_shots_fired.as_slice(),
        "time_scale_active": state.time_scale_active,
        "game_tune_started": state.game_tune_started,
        "debug_hit_sfx_draws_tick": state.debug_hit_sfx_draws_tick,
        "debug_death_sfx_draws_tick": state.debug_death_sfx_draws_tick,
        "debug_bonus_flow_draws_tick": state.debug_bonus_flow_draws_tick,
        "debug_weapon_pick_draws_tick": state.debug_weapon_pick_draws_tick,
        "debug_projectile_hits_tick": state.debug_projectile_hits_tick,
        "debug_projectile_hits_detail_tick": debug_projectile_hits_detail_tick,
    });
    serde_json::to_writer(&mut *writer, &row)
        .map_err(|err| VerifyError::Io(std::io::Error::other(err)))?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_close(actual: f32, expected: f32) {
        let delta = (actual - expected).abs();
        assert!(
            delta <= 1e-4,
            "expected {expected}, got {actual} (delta={delta})"
        );
    }

    #[test]
    fn advance_survival_spawn_stage_thresholds_match_python() {
        let cases = [
            (0, 4, 0, 0),
            (0, 5, 1, 2),
            (0, 20, 7, 29),
            (1, 8, 1, 0),
            (1, 9, 2, 1),
            (2, 10, 2, 0),
            (2, 11, 3, 12),
            (3, 13, 4, 4),
            (4, 15, 5, 8),
            (5, 17, 6, 1),
            (6, 19, 7, 1),
            (7, 21, 8, 2),
            (8, 26, 9, 8),
            (9, 31, 9, 0),
            (9, 32, 10, 10),
        ];
        for (stage, level, expected_stage, expected_count) in cases {
            let (new_stage, spawns) = advance_survival_spawn_stage(stage, level);
            assert_eq!(new_stage, expected_stage);
            assert_eq!(spawns.len(), expected_count);
        }
    }

    #[test]
    fn advance_survival_spawn_stage_stage2_grid_positions_match_python() {
        let (stage, spawns) = advance_survival_spawn_stage(2, 11);
        assert_eq!(stage, 3);
        assert_eq!(spawns.len(), 12);
        assert!(spawns
            .iter()
            .all(|entry| entry.template_id == SPAWN_ID_SPIDER_SP2_RANDOM_35));
        assert!(spawns
            .iter()
            .all(|entry| (entry.heading - std::f32::consts::PI).abs() <= f32::EPSILON));

        assert_close(spawns[0].pos.x, 1088.0);
        assert_close(spawns[0].pos.y, 256.0);
        assert_close(spawns[11].pos.x, 1088.0);
        assert_close(spawns[11].pos.y, 256.0 + 11.0 * (128.0 / 3.0));
    }

    #[test]
    fn advance_survival_spawn_stage_stage9_final_wave_match_python() {
        let (stage, spawns) = advance_survival_spawn_stage(9, 32);
        assert_eq!(stage, 10);
        assert_eq!(spawns.len(), 10);

        assert_eq!(
            spawns[0].template_id,
            SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A
        );
        assert_eq!(
            spawns[1].template_id,
            SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A
        );
        assert_close(spawns[0].pos.x, 1088.0);
        assert_close(spawns[0].pos.y, 512.0);
        assert_close(spawns[1].pos.x, -64.0);
        assert_close(spawns[1].pos.y, 512.0);

        for entry in &spawns[2..6] {
            assert_eq!(
                entry.template_id,
                SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C
            );
            assert_close(entry.pos.y, -64.0);
        }
        for entry in &spawns[6..10] {
            assert_eq!(
                entry.template_id,
                SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C
            );
            assert_close(entry.pos.y, 1088.0);
        }
    }

    #[test]
    fn tick_survival_wave_spawns_no_trigger_matches_python() {
        let mut rng = CrtRand::new(123);
        let (cooldown, spawns) =
            tick_survival_wave_spawns(100.0, 16.0, &mut rng, 2, 0.0, 0, 1024, 1024);

        assert_close(cooldown as f32, 68.0);
        assert!(spawns.is_empty());
        assert_eq!(rng.state(), 123);
    }

    #[test]
    fn tick_survival_wave_spawns_single_spawn_matches_python() {
        let mut rng = CrtRand::new(1);
        let (cooldown, spawns) =
            tick_survival_wave_spawns(-1.0, 0.0, &mut rng, 1, 0.0, 0, 1024, 1024);

        assert_close(cooldown as f32, 499.0);
        assert_eq!(spawns.len(), 1);
        let creature = spawns[0];
        assert_close(creature.pos.x, 35.0);
        assert_close(creature.pos.y, 1064.0);
        assert_eq!(creature.type_id, CREATURE_TYPE_ALIEN);
        assert_close(creature.health, 85.0);
        assert_close(creature.reward_value, 336.0);
        assert_eq!(rng.state(), 0xA6E9C9A6);
    }

    #[test]
    fn tick_survival_wave_spawns_extra_spawns_match_python() {
        let mut rng = CrtRand::new(1);
        let (cooldown, spawns) =
            tick_survival_wave_spawns(-1.0, 0.0, &mut rng, 1, 905_400.0, 0, 1024, 1024);

        assert_close(cooldown as f32, 0.0);
        assert_eq!(spawns.len(), 3);

        assert_close(spawns[0].pos.x, 35.0);
        assert_close(spawns[0].pos.y, 1064.0);
        assert_close(spawns[1].pos.x, 1064.0);
        assert_close(spawns[1].pos.y, 947.0);
        assert_close(spawns[2].pos.x, -40.0);
        assert_close(spawns[2].pos.y, 435.0);

        assert_eq!(spawns[0].type_id, CREATURE_TYPE_ALIEN);
        assert_eq!(spawns[1].type_id, CREATURE_TYPE_ALIEN);
        assert_eq!(spawns[2].type_id, CREATURE_TYPE_SPIDER_SP1);
        assert_eq!(rng.state(), 0xBB25E9C6);
    }
}
