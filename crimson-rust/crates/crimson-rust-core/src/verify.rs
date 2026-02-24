#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bootstrap::{apply_replay_bootstrap, ReplayBootstrapError};
use crate::rand::CrtRand;
use crate::replay::{load_replay, Replay, ReplayCodecError, ReplayEvent};

pub const REPLAY_VERIFY_SCHEMA_VERSION: i64 = 1;
pub const REPLAY_VERIFY_SCORE_MISMATCH_EXIT_CODE: i32 = 3;

const FIRE_DOWN_FLAG: i64 = 1 << 0;
const FIRE_PRESSED_FLAG: i64 = 1 << 1;
const RELOAD_PRESSED_FLAG: i64 = 1 << 2;

const PISTOL_WEAPON_ID: i64 = 1;
const PISTOL_CLIP_SIZE: i64 = 10;
const PISTOL_SHOT_COOLDOWN_S: f32 = 0.7117;
const PISTOL_RELOAD_TIME_S: f32 = 1.2;

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

#[derive(Debug, Clone, Copy)]
struct SurvivalSubsetPlayer {
    ammo: f32,
    clip_size: i64,
    shot_cooldown_s: f32,
    reload_timer_s: f32,
    reload_active: bool,
}

impl SurvivalSubsetPlayer {
    fn new() -> Self {
        Self {
            ammo: PISTOL_CLIP_SIZE as f32,
            clip_size: PISTOL_CLIP_SIZE,
            shot_cooldown_s: 0.0,
            reload_timer_s: 0.0,
            reload_active: false,
        }
    }

    fn step(
        &mut self,
        dt_s: f32,
        fire_down: bool,
        fire_pressed: bool,
        reload_pressed: bool,
        rng: &mut CrtRand,
    ) -> i64 {
        self.advance_timers(dt_s);

        if reload_pressed {
            self.start_reload_if_needed();
        }

        // In the native loop, fire_down is the gate for continuous fire, and
        // fire_pressed helps the first-shot edge. The subset keeps both.
        let wants_fire = fire_down || fire_pressed;
        if !wants_fire {
            return 0;
        }

        if self.reload_active || self.shot_cooldown_s > 0.0 || self.ammo < 1.0 {
            return 0;
        }

        self.ammo -= 1.0;
        self.shot_cooldown_s = PISTOL_SHOT_COOLDOWN_S;

        // Pistol fire path consumes several RNG draws in native gameplay
        // (spread/audio and related per-shot side effects).
        for _ in 0..3 {
            rng.rand();
        }

        if self.ammo < 1.0 {
            self.start_reload_if_needed();
        }

        1
    }

    fn advance_timers(&mut self, dt_s: f32) {
        if self.shot_cooldown_s > 0.0 {
            self.shot_cooldown_s = (self.shot_cooldown_s - dt_s).max(0.0);
        }
        if self.reload_active {
            self.reload_timer_s = (self.reload_timer_s - dt_s).max(0.0);
            if self.reload_timer_s <= 0.0 {
                self.reload_active = false;
                self.ammo = self.clip_size as f32;
            }
        }
    }

    fn start_reload_if_needed(&mut self) {
        if self.reload_active {
            return;
        }
        if self.ammo >= self.clip_size as f32 {
            return;
        }
        self.reload_active = true;
        self.reload_timer_s = PISTOL_RELOAD_TIME_S;
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
    if replay.header.game_mode_id != 1 {
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

    let mut rng = CrtRand::new(0);
    let _ = apply_replay_bootstrap(&replay.header, &mut rng, replay.header.world_size, true)?;

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

    let mut player = SurvivalSubsetPlayer::new();
    let dt_s = (1.0_f32 / tick_rate as f32).max(0.0);

    let mut elapsed_ms: f64 = 0.0;
    let mut shots_fired: i64 = 0;
    let mut shot_counts_by_weapon: [i64; 54] = [0; 54];

    for tick in 0..ticks_total {
        apply_phase1_events(&events_by_tick[tick], &mut rng)?;

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

        let (fire_down, fire_pressed, reload_pressed) = unpack_input_flags(packed.flags);
        let fired = player.step(dt_s, fire_down, fire_pressed, reload_pressed, &mut rng);
        shots_fired += fired;
        if fired > 0 {
            let idx = usize::try_from(PISTOL_WEAPON_ID).unwrap_or(1);
            if idx < shot_counts_by_weapon.len() {
                shot_counts_by_weapon[idx] += fired;
            }
        }
        elapsed_ms += f64::from(dt_s) * 1000.0;
    }

    // Replay-side terminal events may exist at tick == len(inputs).
    apply_phase1_events(&events_by_tick[ticks_total], &mut rng)?;

    let most_used_weapon_id = most_used_weapon_id(PISTOL_WEAPON_ID, &shot_counts_by_weapon);

    Ok(RunResult {
        game_mode_id: replay.header.game_mode_id,
        tick_rate,
        ticks: i64::try_from(ticks_total).unwrap_or(i64::MAX),
        elapsed_ms: elapsed_ms as i64,
        score_xp: 0,
        creature_kill_count: 0,
        most_used_weapon_id,
        shots_fired,
        shots_hit: 0,
        rng_state: u64::from(rng.state()),
    })
}

fn apply_phase1_events(events: &[&ReplayEvent], rng: &mut CrtRand) -> Result<(), VerifyError> {
    for event in events {
        match event {
            ReplayEvent::PerkMenuOpen(_) => {
                // Choice regeneration in Python consumes RNG. Phase-1 subset only
                // tracks deterministic draw count for event ordering parity.
                for _ in 0..3 {
                    rng.rand();
                }
            }
            ReplayEvent::PerkPick(_) => {
                // Perk apply side effects are not yet ported; consume one draw to
                // keep stream movement deterministic under recorded picks.
                rng.rand();
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("{digest:x}")
}
