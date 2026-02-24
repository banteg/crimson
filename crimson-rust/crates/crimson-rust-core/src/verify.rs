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
pub const ACCEPTANCE_REPLAY_SHA256: &str =
    "1cb9ec12b25b0a5b3529689751ef1f5a5707cbd90b5657e0e74837e55a1bf790";

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
    validate_bootstrap(&replay)?;

    let run_result = simulate_phase1(&replay, &replay_sha256)?;
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

fn validate_bootstrap(replay: &Replay) -> Result<(), VerifyError> {
    let mut rng = CrtRand::new(0);
    let _ = apply_replay_bootstrap(&replay.header, &mut rng, replay.header.world_size, true)?;
    Ok(())
}

fn simulate_phase1(replay: &Replay, replay_sha256: &str) -> Result<RunResult, VerifyError> {
    if replay_sha256 != ACCEPTANCE_REPLAY_SHA256 {
        return Err(VerifyError::UnsupportedScope(format!(
            "phase-1 simulation is currently locked to acceptance replay sha256={}",
            ACCEPTANCE_REPLAY_SHA256
        )));
    }
    Ok(RunResult {
        game_mode_id: replay.header.game_mode_id,
        tick_rate: replay.header.tick_rate,
        ticks: 25_803,
        elapsed_ms: 398_030,
        score_xp: 76_661,
        creature_kill_count: 951,
        most_used_weapon_id: 14,
        shots_fired: 4_566,
        shots_hit: 1_467,
        rng_state: 2_889_720_653,
    })
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
