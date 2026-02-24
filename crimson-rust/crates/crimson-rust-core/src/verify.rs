#![forbid(unsafe_code)]

use std::fs;
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

const GAME_MODE_SURVIVAL: i64 = 1;
const GAME_MODE_QUESTS: i64 = 3;

const PERK_COUNT_SIZE: usize = 0x80;
const WEAPON_COUNT_SIZE: usize = 0x80;
const WEAPON_USAGE_COUNT: usize = 53;
const WEAPON_DROP_ID_COUNT: u32 = 0x21;

const PERK_FLAGS_QUEST_ALLOWED: u8 = 0x1;
const PERK_FLAGS_TWO_PLAYER_ALLOWED: u8 = 0x2;
const PERK_FLAGS_STACKABLE: u8 = 0x4;

const PERK_ANTIPERK: usize = 0;
const PERK_SHARPSHOOTER: usize = 2;
const PERK_FASTLOADER: usize = 3;
const PERK_FASTSHOT: usize = 14;
const PERK_FATAL_LOTTERY: usize = 15;
const PERK_RANDOM_WEAPON: usize = 16;
const PERK_ANXIOUS_LOADER: usize = 18;
const PERK_PERK_EXPERT: usize = 21;
const PERK_REGRESSION_BULLETS: usize = 23;
const PERK_INFERNAL_CONTRACT: usize = 24;
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

const WEAPON_PISTOL: i64 = 1;
const WEAPON_ASSAULT_RIFLE: i64 = 2;
const WEAPON_SHOTGUN: i64 = 3;
const WEAPON_SAWED_OFF_SHOTGUN: i64 = 4;
const WEAPON_SUBMACHINE_GUN: i64 = 5;
const WEAPON_FLAMETHROWER: i64 = 8;
const WEAPON_MULTI_PLASMA: i64 = 10;
const WEAPON_PLASMA_SHOTGUN: i64 = 14;
const WEAPON_JACKHAMMER: i64 = 20;
const WEAPON_GAUSS_SHOTGUN: i64 = 30;
const WEAPON_ION_SHOTGUN: i64 = 31;
const WEAPON_FIRE_BULLETS: i64 = 45;

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
const CREATURE_TYPE_ALIEN: i32 = 2;
const CREATURE_TYPE_SPIDER_SP1: i32 = 3;
const CREATURE_TYPE_SPIDER_SP2: i32 = 4;

const CREATURE_AI_MODE_ORBIT_PLAYER: i32 = 0;
const CREATURE_FLAG_AI7_LINK_TIMER: u32 = 0x80;

const SPAWN_ID_SPIDER_SP2_SPLITTER_01: i32 = 0x01;
const SPAWN_ID_FORMATION_RING_ALIEN_8_12: i32 = 0x12;
const SPAWN_ID_ALIEN_CONST_RED_FAST_2B: i32 = 0x2B;
const SPAWN_ID_ALIEN_CONST_RED_BOSS_2C: i32 = 0x2C;
const SPAWN_ID_SPIDER_SP2_RANDOM_35: i32 = 0x35;
const SPAWN_ID_SPIDER_SP1_AI7_TIMER_38: i32 = 0x38;
const SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A: i32 = 0x3A;
const SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C: i32 = 0x3C;

const RANDOM_HEADING_SENTINEL: f32 = -100.0;
const SURVIVAL_SPAWN_EDGE_OFFSET: f32 = 40.0;
const SURVIVAL_RUNTIME_PROJECTILE_MARGIN: f32 = 64.0;
const SURVIVAL_RUNTIME_CREATURE_MARGIN: f32 = 96.0;
const SURVIVAL_RUNTIME_CREATURE_SPEED_SCALE: f32 = 30.0;
const SURVIVAL_RUNTIME_MAX_ENTITIES: usize = 8192;

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
    weapon_id: i64,
    clip_size: i64,
    ammo: f32,
    reload_active: bool,
    reload_timer: f32,
    reload_timer_max: f32,
    shot_cooldown: f32,
    spread_heat: f32,
    experience: i64,
    level: i64,
    health: f32,
    perk_counts: [i32; PERK_COUNT_SIZE],
}

impl Default for PlayerState {
    fn default() -> Self {
        Self {
            weapon_id: WEAPON_PISTOL,
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
            perk_counts: [0; PERK_COUNT_SIZE],
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
    type_id: i32,
    flags: u32,
    ai_mode: i32,
    health: f32,
    max_health: f32,
    move_speed: f32,
    reward_value: f32,
    size: f32,
    contact_damage: f32,
    tint: [f32; 4],
}

#[derive(Debug, Clone, Copy)]
struct RuntimeCreature {
    active: bool,
    pos: Vec2f,
    heading: f32,
    type_id: i32,
    flags: u32,
    ai_mode: i32,
    health: f32,
    max_health: f32,
    move_speed: f32,
    reward_value: f32,
    size: f32,
    contact_damage: f32,
    tint: [f32; 4],
}

impl RuntimeCreature {
    fn from_survival_spawn(creature: SurvivalSpawnCreature) -> Self {
        Self {
            active: true,
            pos: creature.pos,
            heading: creature.heading,
            type_id: creature.type_id,
            flags: creature.flags,
            ai_mode: creature.ai_mode,
            health: creature.health,
            max_health: creature.max_health,
            move_speed: creature.move_speed,
            reward_value: creature.reward_value,
            size: creature.size,
            contact_damage: creature.contact_damage,
            tint: creature.tint,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RuntimeProjectile {
    active: bool,
    pos: Vec2f,
    origin: Vec2f,
    angle: f32,
    type_id: i64,
    base_damage: f32,
    speed_scale: f32,
    damage_pool: f32,
    hit_radius: f32,
    life_timer: f32,
}

#[derive(Debug, Clone)]
struct SimState {
    rng: CrtRand,
    game_mode: i64,
    preserve_bugs: bool,
    hardcore: bool,
    player_count: i64,
    quest_stage_major: i64,
    quest_stage_minor: i64,
    quest_unlock_index: i64,
    quest_unlock_index_full: i64,

    player: PlayerState,
    perk_selection: PerkSelectionState,

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
    survival_spawn_cooldown_ms: f32,
    survival_terrain_width: i32,
    survival_terrain_height: i32,
    player_pos: Vec2f,
    creatures: Vec<RuntimeCreature>,
    projectiles: Vec<RuntimeProjectile>,
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
            player_count: replay.header.player_count,
            quest_stage_major: 0,
            quest_stage_minor: 0,
            quest_unlock_index: replay.header.status.quest_unlock_index,
            quest_unlock_index_full: replay.header.status.quest_unlock_index_full,

            player: PlayerState::default(),
            perk_selection: PerkSelectionState::default(),

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
            creatures: Vec::new(),
            projectiles: Vec::new(),
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

    let dt_s = (1.0_f32 / tick_rate as f32).max(0.0);
    let dt_ms = dt_s * 1000.0;
    let mut elapsed_ms: f64 = 0.0;

    for tick in 0..ticks_total {
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
        let (fire_down, fire_pressed, reload_pressed) = unpack_input_flags(packed.flags);
        let elapsed_before_ms = elapsed_ms;
        player_step(
            &mut state,
            dt_s,
            move_input,
            aim,
            fire_down,
            fire_pressed,
            reload_pressed,
        );
        survival_mid_step_spawns(&mut state, dt_ms, elapsed_before_ms as f32);
        survival_runtime_tick(&mut state, dt_s);
        survival_progression_update(&mut state);
        elapsed_ms += f64::from(dt_ms);
    }

    apply_phase1_events(
        &events_by_tick[ticks_total],
        i64::try_from(ticks_total).unwrap_or(i64::MAX),
        &mut state,
    )?;

    let most_used_weapon_id =
        most_used_weapon_id(state.player.weapon_id, &state.weapon_shots_fired);

    Ok(RunResult {
        game_mode_id: replay.header.game_mode_id,
        tick_rate,
        ticks: i64::try_from(ticks_total).unwrap_or(i64::MAX),
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
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
) {
    player_update_position(state, move_input, dt);

    let should_start_reload = {
        let player = &mut state.player;

        let cooldown_decay = dt;
        player.shot_cooldown = (player.shot_cooldown - cooldown_decay).max(0.0);
        if player.shot_cooldown > 0.0 && player.shot_cooldown < 1e-6 {
            player.shot_cooldown = 0.0;
        }

        if perk_active(player, PERK_ANXIOUS_LOADER) && fire_pressed && player.reload_timer > 0.0 {
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
                    // Native fires a plasma ring here; projectile runtime not ported yet.
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

        let should_start_reload_local = reload_pressed && player.reload_timer == 0.0;

        if player.shot_cooldown <= 0.0 && player.reload_timer == 0.0 {
            player.reload_active = false;
        }
        should_start_reload_local
    };
    if should_start_reload {
        player_start_reload(state);
    }

    if fire_down {
        let _ = player_fire_weapon(state, aim, fire_down, fire_pressed);
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

        let mut shot_cooldown = weapon.shot_cooldown_s;
        if perk_active(player, PERK_FASTSHOT) {
            shot_cooldown *= 0.88;
        }
        if perk_active(player, PERK_SHARPSHOOTER) {
            shot_cooldown *= 1.05;
        }
        player.shot_cooldown = shot_cooldown.max(0.0);

        let (current_shot_count, rng_draws, ammo_cost) =
            shot_pattern_and_rng(player.weapon_id, weapon.pellet_count);
        for _ in 0..rng_draws {
            state.rng.rand();
        }

        state.shots_fired += current_shot_count;
        let weapon_idx = usize::try_from(player.weapon_id).unwrap_or(0);
        if weapon_idx < state.weapon_shots_fired.len() {
            state.weapon_shots_fired[weapon_idx] += current_shot_count;
        }

        if !perk_active(player, PERK_SHARPSHOOTER) {
            player.spread_heat = (player.spread_heat + 0.06).clamp(0.01, 0.48);
        }

        if player.weapon_id != WEAPON_FIRE_BULLETS {
            player.ammo -= ammo_cost;
        }
        if player.ammo <= 0.0 && player.reload_timer <= 0.0 {
            needs_reload_start = true;
        }

        shot_count = current_shot_count;
    }

    if needs_reload_start {
        player_start_reload(state);
    }
    if shot_count > 0 {
        spawn_player_projectiles(state, aim, shot_count);
    }
    shot_count
}

fn shot_pattern_and_rng(weapon_id: i64, pellet_count: i16) -> (i64, u32, f32) {
    let mut shot_count = if pellet_count <= 0 {
        1
    } else {
        i64::from(pellet_count)
    };
    let mut ammo_cost = 1.0_f32;

    match weapon_id {
        WEAPON_MULTI_PLASMA => {
            shot_count = 5;
        }
        WEAPON_PLASMA_SHOTGUN => {
            shot_count = 14;
        }
        WEAPON_GAUSS_SHOTGUN => {
            shot_count = 6;
        }
        WEAPON_ION_SHOTGUN => {
            shot_count = 8;
        }
        _ => {}
    }

    // Approximate native draw shape for spread/audio/per-pellet jitter paths.
    let mut draws: u32 = 3;
    match weapon_id {
        WEAPON_PLASMA_SHOTGUN | WEAPON_GAUSS_SHOTGUN | WEAPON_ION_SHOTGUN => {
            draws = draws.saturating_add((shot_count as u32).saturating_mul(2));
        }
        WEAPON_SHOTGUN | WEAPON_SAWED_OFF_SHOTGUN | WEAPON_JACKHAMMER => {
            draws = draws.saturating_add((shot_count as u32).saturating_mul(2));
        }
        _ => {
            if shot_count > 1 {
                draws = draws.saturating_add(shot_count as u32);
            }
        }
    }

    // Mini-rocket swarmers spends full clip per shot in native.
    if weapon_id == 17 {
        ammo_cost = shot_count as f32;
    }

    (shot_count.max(0), draws, ammo_cost.max(0.0))
}

fn spawn_player_projectiles(state: &mut SimState, aim: Vec2f, shot_count: i64) {
    if state.projectiles.len() >= SURVIVAL_RUNTIME_MAX_ENTITIES {
        return;
    }

    let projectile_count = usize::try_from(shot_count.max(1)).unwrap_or(1);
    let capped_count = projectile_count
        .min(SURVIVAL_RUNTIME_MAX_ENTITIES)
        .min(SURVIVAL_RUNTIME_MAX_ENTITIES.saturating_sub(state.projectiles.len()));
    if capped_count == 0 {
        return;
    }

    let direction = aim.sub(state.player_pos).normalized_or_zero();
    let fallback_direction = Vec2f { x: 1.0, y: 0.0 };
    let base_dir = if direction.length_sq() <= f32::EPSILON {
        fallback_direction
    } else {
        direction
    };
    let base_heading = base_dir.y.atan2(base_dir.x);
    let weapon_id = state.player.weapon_id;
    let spread_span = projectile_spread_span_for_weapon(weapon_id, capped_count);
    let spread_step = if capped_count > 1 {
        spread_span / (capped_count as f32 - 1.0)
    } else {
        0.0
    };
    let spread_start = -spread_span * 0.5;

    let multi_plasma_patterns: [(f32, i64); 5] = [
        (-std::f32::consts::PI * 0.1, PROJECTILE_TYPE_PLASMA_RIFLE),
        (-std::f32::consts::PI / 6.0, PROJECTILE_TYPE_PLASMA_MINIGUN),
        (0.0, PROJECTILE_TYPE_PLASMA_RIFLE),
        (std::f32::consts::PI / 6.0, PROJECTILE_TYPE_PLASMA_MINIGUN),
        (std::f32::consts::PI * 0.1, PROJECTILE_TYPE_PLASMA_RIFLE),
    ];

    for pellet_idx in 0..capped_count {
        let mut heading = base_heading + spread_start + spread_step * pellet_idx as f32;
        let mut type_id =
            projectile_type_id_from_weapon_id(weapon_id).unwrap_or(PROJECTILE_TYPE_PISTOL);
        if weapon_id == WEAPON_PLASMA_SHOTGUN {
            type_id = PROJECTILE_TYPE_PLASMA_MINIGUN;
        } else if weapon_id == WEAPON_GAUSS_SHOTGUN {
            type_id = PROJECTILE_TYPE_GAUSS_GUN;
        } else if weapon_id == WEAPON_ION_SHOTGUN {
            type_id = PROJECTILE_TYPE_ION_MINIGUN;
        } else if weapon_id == WEAPON_MULTI_PLASMA {
            let pattern = multi_plasma_patterns
                .get(pellet_idx.min(multi_plasma_patterns.len().saturating_sub(1)))
                .copied()
                .unwrap_or((0.0, PROJECTILE_TYPE_PLASMA_RIFLE));
            heading = base_heading + pattern.0;
            type_id = pattern.1;
        }

        let speed_scale = projectile_speed_scale_for_weapon(weapon_id, pellet_idx, capped_count);
        let (base_damage, damage_pool, hit_radius, life_timer) =
            projectile_init_fields_for_type(type_id);
        state.projectiles.push(RuntimeProjectile {
            active: true,
            pos: state.player_pos,
            origin: state.player_pos,
            angle: heading,
            type_id,
            base_damage,
            speed_scale,
            damage_pool,
            hit_radius,
            life_timer,
        });
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

fn projectile_speed_scale_for_weapon(
    weapon_id: i64,
    pellet_idx: usize,
    projectile_count: usize,
) -> f32 {
    let spread_t = if projectile_count <= 1 {
        0.0
    } else {
        pellet_idx as f32 / (projectile_count as f32 - 1.0)
    };
    match weapon_id {
        WEAPON_GAUSS_SHOTGUN | WEAPON_ION_SHOTGUN => 1.4 + spread_t * 0.79,
        WEAPON_SHOTGUN | WEAPON_SAWED_OFF_SHOTGUN | WEAPON_JACKHAMMER | WEAPON_PLASMA_SHOTGUN => {
            1.0 + spread_t * 0.99
        }
        _ => 1.0,
    }
}

fn projectile_spread_span_for_weapon(weapon_id: i64, projectile_count: usize) -> f32 {
    if projectile_count <= 1 {
        return 0.0;
    }
    match weapon_id {
        WEAPON_SHOTGUN | WEAPON_SAWED_OFF_SHOTGUN | WEAPON_JACKHAMMER => 0.44,
        WEAPON_PLASMA_SHOTGUN => 0.50,
        WEAPON_GAUSS_SHOTGUN | WEAPON_ION_SHOTGUN => 0.48,
        _ => 0.20,
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

    if !player.reload_active {
        player.reload_active = true;
    }
    player.reload_timer = reload_time.max(0.0);
    player.reload_timer_max = player.reload_timer;
}

fn weapon_assign_player(state: &mut SimState, weapon_id: i64) {
    let player = &mut state.player;
    player.weapon_id = weapon_id;

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

fn survival_mid_step_spawns(state: &mut SimState, frame_dt_ms: f32, survival_elapsed_ms: f32) {
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
    spawn_cooldown: f32,
    frame_dt_ms: f32,
    rng: &mut CrtRand,
    player_count: i32,
    survival_elapsed_ms: f32,
    player_experience: i64,
    terrain_width: i32,
    terrain_height: i32,
) -> (f32, Vec<SurvivalSpawnCreature>) {
    let mut cooldown = spawn_cooldown - (player_count as f32) * frame_dt_ms;
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
    cooldown += interval_ms as f32;

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
    consume_survival_template_build_rng(&mut state.rng, call.template_id, call.heading);
    spawn_survival_template_runtime_creatures(state, call);

    if call.pos.x > 0.0
        && call.pos.x < state.survival_terrain_width as f32
        && call.pos.y > 0.0
        && call.pos.y < state.survival_terrain_height as f32
    {
        consume_spawn_burst_rng(&mut state.rng, 8);
    }
}

fn runtime_spawn_survival_creature(state: &mut SimState, creature: SurvivalSpawnCreature) {
    if state.creatures.len() >= SURVIVAL_RUNTIME_MAX_ENTITIES {
        return;
    }
    state
        .creatures
        .push(RuntimeCreature::from_survival_spawn(creature));
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
) {
    if state.creatures.len() >= SURVIVAL_RUNTIME_MAX_ENTITIES {
        return;
    }
    state.creatures.push(RuntimeCreature {
        active: true,
        pos,
        heading,
        type_id,
        flags,
        ai_mode,
        health,
        max_health: health,
        move_speed,
        reward_value,
        size,
        contact_damage,
        tint,
    });
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
            runtime_spawn_template_creature(
                state,
                call.pos,
                call.heading,
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
            let angle_step = std::f32::consts::PI / 4.0;
            for idx in 0..8 {
                let angle = idx as f32 * angle_step;
                let offset = Vec2f {
                    x: angle.cos() * 100.0,
                    y: angle.sin() * 100.0,
                };
                runtime_spawn_template_creature(
                    state,
                    call.pos.add(offset),
                    call.heading,
                    CREATURE_TYPE_ALIEN,
                    0,
                    CREATURE_AI_MODE_ORBIT_PLAYER,
                    40.0,
                    2.4,
                    60.0,
                    50.0,
                    4.0,
                    [0.32, 0.588, 0.426, 1.0],
                );
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
            runtime_spawn_template_creature(
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

fn alloc_survival_spawn_creature(pos: Vec2f, rng: &mut CrtRand) -> SurvivalSpawnCreature {
    SurvivalSpawnCreature {
        pos,
        heading: 0.0,
        phase_seed: (rng.rand() & 0x17F) as f32,
        type_id: -1,
        flags: 0,
        ai_mode: CREATURE_AI_MODE_ORBIT_PLAYER,
        health: 0.0,
        max_health: 0.0,
        move_speed: 0.0,
        reward_value: 0.0,
        size: 0.0,
        contact_damage: 0.0,
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

fn player_update_position(state: &mut SimState, move_input: Vec2f, dt_s: f32) {
    if dt_s <= 0.0 {
        return;
    }

    let mut move_dir = move_input;
    let len_sq = move_dir.length_sq();
    if len_sq > 1.0 {
        move_dir = move_dir.normalized_or_zero();
    }

    let speed = 30.0_f32;
    let delta = move_dir.scale(speed * dt_s);
    let next = state.player_pos.add(delta);

    let min_x = 0.0_f32;
    let min_y = 0.0_f32;
    let max_x = state.survival_terrain_width as f32;
    let max_y = state.survival_terrain_height as f32;
    state.player_pos = Vec2f {
        x: next.x.clamp(min_x, max_x),
        y: next.y.clamp(min_y, max_y),
    };
}

fn survival_runtime_tick(state: &mut SimState, dt_s: f32) {
    if dt_s <= 0.0 {
        return;
    }

    survival_runtime_update_creatures(state, dt_s);
    survival_runtime_update_projectiles(state, dt_s);

    let min_x = -SURVIVAL_RUNTIME_CREATURE_MARGIN;
    let min_y = -SURVIVAL_RUNTIME_CREATURE_MARGIN;
    let max_x = state.survival_terrain_width as f32 + SURVIVAL_RUNTIME_CREATURE_MARGIN;
    let max_y = state.survival_terrain_height as f32 + SURVIVAL_RUNTIME_CREATURE_MARGIN;
    state.projectiles.retain(|entry| entry.active);
    state.creatures.retain(|entry| {
        entry.active
            && entry.health > 0.0
            && min_x <= entry.pos.x
            && entry.pos.x <= max_x
            && min_y <= entry.pos.y
            && entry.pos.y <= max_y
    });
}

fn survival_runtime_update_creatures(state: &mut SimState, dt_s: f32) {
    for creature in &mut state.creatures {
        if !creature.active || creature.health <= 0.0 {
            continue;
        }
        let to_player = state.player_pos.sub(creature.pos);
        let dir = to_player.normalized_or_zero();
        if dir.length_sq() <= f32::EPSILON {
            continue;
        }

        let type_scale = match creature.type_id {
            CREATURE_TYPE_ZOMBIE => 0.85,
            CREATURE_TYPE_SPIDER_SP1 => 1.05,
            CREATURE_TYPE_SPIDER_SP2 => 1.1,
            _ => 1.0,
        };
        let ai_scale = if creature.ai_mode == CREATURE_AI_MODE_ORBIT_PLAYER {
            1.0
        } else {
            1.05
        };
        let flag_scale = if (creature.flags & CREATURE_FLAG_AI7_LINK_TIMER) != 0 {
            1.08
        } else {
            1.0
        };
        let hp_ratio = if creature.max_health > 0.0 {
            (creature.health / creature.max_health).clamp(0.35, 1.0)
        } else {
            1.0
        };
        let tint_scale = (creature.tint[0] + creature.tint[1] + creature.tint[2]) * (1.0 / 3.0);
        let contact_scale = (1.0 + creature.contact_damage * 0.002).clamp(0.9, 1.2);

        let speed = creature.move_speed.max(0.0)
            * SURVIVAL_RUNTIME_CREATURE_SPEED_SCALE
            * type_scale
            * ai_scale
            * flag_scale
            * contact_scale
            * (0.6 + hp_ratio * 0.4)
            * (0.9 + tint_scale * 0.1);
        let delta = dir.scale(speed * dt_s);
        creature.pos = creature.pos.add(delta);
        creature.heading = dir.y.atan2(dir.x);
    }
}

fn survival_runtime_update_projectiles(state: &mut SimState, dt_s: f32) {
    let min_x = -SURVIVAL_RUNTIME_PROJECTILE_MARGIN;
    let min_y = -SURVIVAL_RUNTIME_PROJECTILE_MARGIN;
    let max_x = state.survival_terrain_width as f32 + SURVIVAL_RUNTIME_PROJECTILE_MARGIN;
    let max_y = state.survival_terrain_height as f32 + SURVIVAL_RUNTIME_PROJECTILE_MARGIN;

    for proj_idx in 0..state.projectiles.len() {
        if !state.projectiles[proj_idx].active {
            continue;
        }

        if state.projectiles[proj_idx].life_timer <= 0.0 {
            state.projectiles[proj_idx].active = false;
            continue;
        }
        if state.projectiles[proj_idx].life_timer < 0.4 {
            state.projectiles[proj_idx].life_timer -= dt_s;
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

        let direction = {
            let proj = &state.projectiles[proj_idx];
            Vec2f {
                x: proj.angle.cos(),
                y: proj.angle.sin(),
            }
        };
        let step_scale = dt_s * 20.0 * state.projectiles[proj_idx].speed_scale * 3.0;
        let mut acc = Vec2f { x: 0.0, y: 0.0 };
        let mut step = 0_i32;
        while step < steps {
            acc = acc.add(direction.scale(step_scale));
            let acc_len = acc.length_sq().sqrt();
            if acc_len >= 4.0 || steps <= step + 3 {
                let move_delta = acc;
                acc = Vec2f { x: 0.0, y: 0.0 };
                state.projectiles[proj_idx].pos = state.projectiles[proj_idx].pos.add(move_delta);

                let mut hit_creature_idx: Option<usize> = None;
                let hit_origin = state.projectiles[proj_idx].pos;
                let hit_radius = state.projectiles[proj_idx].hit_radius;
                for creature_idx in 0..state.creatures.len() {
                    let creature = &state.creatures[creature_idx];
                    if !creature.active || creature.health <= 0.0 {
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
                    step += 3;
                    continue;
                };

                state.shots_hit = state.shots_hit.saturating_add(1);
                let type_id = state.projectiles[proj_idx].type_id;
                if state.projectiles[proj_idx].life_timer != 0.25
                    && !projectile_is_piercing_type(type_id)
                {
                    state.projectiles[proj_idx].life_timer = 0.25;
                }

                let mut dist = state.projectiles[proj_idx]
                    .origin
                    .sub(state.projectiles[proj_idx].pos)
                    .length_sq()
                    .sqrt();
                if dist < 50.0 {
                    dist = 50.0;
                }
                let damage_scale = projectile_damage_scale_for_type(type_id);
                let damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95;

                if damage_amount > 0.0
                    && creature_idx < state.creatures.len()
                    && state.creatures[creature_idx].active
                    && state.creatures[creature_idx].health > 0.0
                {
                    let remaining = state.projectiles[proj_idx].damage_pool - 1.0;
                    state.projectiles[proj_idx].damage_pool = remaining;
                    if remaining <= 0.0 {
                        let mut reward_value = None;
                        {
                            let creature = &mut state.creatures[creature_idx];
                            if creature.active && creature.health > 0.0 {
                                creature.health -= damage_amount;
                                if creature.health <= 0.0 {
                                    creature.active = false;
                                    reward_value = Some(creature.reward_value);
                                }
                            }
                        }
                        if let Some(reward) = reward_value {
                            state.creature_kill_count = state.creature_kill_count.saturating_add(1);
                            let _ = award_player_xp_from_creature_reward(&mut state.player, reward);
                        }
                        if state.projectiles[proj_idx].life_timer != 0.25 {
                            state.projectiles[proj_idx].life_timer = 0.25;
                        }
                    } else {
                        let mut creature_hp_after = 0.0;
                        let mut reward_value = None;
                        {
                            let creature = &mut state.creatures[creature_idx];
                            if creature.active && creature.health > 0.0 {
                                creature.health -= remaining;
                                creature_hp_after = creature.health;
                                if creature.health <= 0.0 {
                                    creature.active = false;
                                    reward_value = Some(creature.reward_value);
                                }
                            }
                        }
                        state.projectiles[proj_idx].damage_pool -= creature_hp_after;
                        if let Some(reward) = reward_value {
                            state.creature_kill_count = state.creature_kill_count.saturating_add(1);
                            let _ = award_player_xp_from_creature_reward(&mut state.player, reward);
                        }
                    }
                }

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
    let dx = target.x - origin.x;
    let dy = target.y - origin.y;
    let size_margin = runtime_creature_hit_radius(target_size);
    let max_axis_delta = radius + size_margin;
    if dx.abs() > max_axis_delta || dy.abs() > max_axis_delta {
        return false;
    }
    let margin = (dx * dx + dy * dy).sqrt() - radius - size_margin;
    margin < 0.0
}

fn award_player_xp_from_creature_reward(player: &mut PlayerState, reward_value: f32) -> i64 {
    if reward_value <= 0.0 || !reward_value.is_finite() {
        return 0;
    }
    let reward_f32 = reward_value as f32;
    let before = player.experience;
    let total_f32 = (before as f32 + reward_f32) as f32;
    let after = total_f32 as i64;
    player.experience = after;
    after - before
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

    for _ in 0..1000 {
        let mut weapon_id = i64::from(state.rng.rand() % WEAPON_DROP_ID_COUNT + 1);

        let usage_idx = usize::try_from(weapon_id.max(0)).unwrap_or(0);
        if usage_idx < state.status_weapon_usage_counts.len()
            && state.status_weapon_usage_counts[usage_idx] != 0
            && (state.rng.rand() & 1) == 0
        {
            weapon_id = i64::from(state.rng.rand() % WEAPON_DROP_ID_COUNT + 1);
        }

        let idx = usize::try_from(weapon_id.max(0)).unwrap_or(0);
        if idx < state.weapon_available.len() && state.weapon_available[idx] {
            return weapon_id;
        }
    }

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

fn unpack_input_flags(flags: i64) -> (bool, bool, bool) {
    (
        (flags & FIRE_DOWN_FLAG) != 0,
        (flags & FIRE_PRESSED_FLAG) != 0,
        (flags & RELOAD_PRESSED_FLAG) != 0,
    )
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("{digest:x}")
}
