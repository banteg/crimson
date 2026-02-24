#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use crimson_rust_core::{
    verify_replay_file, ScoreMetric, VerifyError, VerifyOptions,
    REPLAY_VERIFY_SCORE_MISMATCH_EXIT_CODE,
};
use directories::BaseDirs;

#[derive(Debug, Parser)]
#[command(name = "crimson-rust")]
#[command(about = "Crimson replay verifier (phase-1 Rust port)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Verify {
        replay_file: PathBuf,
        #[arg(long = "format", default_value = "human", value_enum)]
        format: OutputFormat,
        #[arg(long = "submitted-score")]
        submitted_score: Option<i64>,
        #[arg(long = "score-metric", default_value = "auto", value_enum)]
        score_metric: CliScoreMetric,
        #[arg(long = "base-dir", alias = "runtime-dir")]
        base_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliScoreMetric {
    Auto,
    #[value(name = "score_xp")]
    ScoreXp,
    #[value(name = "elapsed_ms")]
    ElapsedMs,
}

impl From<CliScoreMetric> for ScoreMetric {
    fn from(value: CliScoreMetric) -> Self {
        match value {
            CliScoreMetric::Auto => ScoreMetric::Auto,
            CliScoreMetric::ScoreXp => ScoreMetric::ScoreXp,
            CliScoreMetric::ElapsedMs => ScoreMetric::ElapsedMs,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify {
            replay_file,
            format,
            submitted_score,
            score_metric,
            base_dir,
        } => {
            let base_dir = base_dir.unwrap_or_else(default_runtime_dir);
            let (replay_path, tried) = resolve_replay_path(&replay_file, &base_dir);
            if !replay_path.is_file() {
                eprintln!("{}", replay_not_found_message(&tried));
                return ExitCode::from(1);
            }

            let options = VerifyOptions {
                submitted_score,
                score_metric: score_metric.into(),
                replay_label: Some(replay_path.to_string_lossy().to_string()),
            };

            match verify_replay_file(&replay_path, options) {
                Ok(payload) => {
                    if matches!(format, OutputFormat::Json) {
                        match serde_json::to_string(&payload) {
                            Ok(json) => println!("{json}"),
                            Err(err) => {
                                eprintln!("replay verification failed: failed to serialize payload: {err}");
                                return ExitCode::from(1);
                            }
                        }
                    } else {
                        let mut message = format!(
                            "{}: ticks={} elapsed_ms={} score_xp={} kills={} most_used_weapon_id={} shots_fired={} shots_hit={} rng_state={}",
                            payload.status,
                            payload.run_result.ticks,
                            payload.run_result.elapsed_ms,
                            payload.run_result.score_xp,
                            payload.run_result.creature_kill_count,
                            payload.run_result.most_used_weapon_id,
                            payload.run_result.shots_fired,
                            payload.run_result.shots_hit,
                            payload.run_result.rng_state
                        );
                        if let Some(score_claim) = &payload.score_claim {
                            message.push_str(&format!(
                                "; score_claim metric={} submitted={} simulated={} match={}",
                                score_claim.metric,
                                score_claim.submitted_score,
                                score_claim.simulated_value,
                                score_claim.match_ok
                            ));
                        }
                        println!("{message}");
                    }

                    if payload
                        .score_claim
                        .as_ref()
                        .is_some_and(|claim| !claim.match_ok)
                    {
                        return ExitCode::from(REPLAY_VERIFY_SCORE_MISMATCH_EXIT_CODE as u8);
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("replay verification failed: {}", render_verify_error(&err));
                    ExitCode::from(1)
                }
            }
        }
    }
}

fn resolve_replay_path(replay_file: &Path, base_dir: &Path) -> (PathBuf, Vec<PathBuf>) {
    let path = replay_file.to_path_buf();
    let mut tried = vec![path.clone()];
    if path.is_file() {
        return (path, tried);
    }
    if !path.is_absolute() && path.components().count() == 1 {
        if let Some(name) = path.file_name() {
            let under_replays = base_dir.join("replays").join(name);
            if !tried.contains(&under_replays) {
                tried.push(under_replays.clone());
                if under_replays.is_file() {
                    return (under_replays, tried);
                }
            }
        }
    }
    (path, tried)
}

fn replay_not_found_message(tried: &[PathBuf]) -> String {
    if tried.is_empty() {
        return "replay file not found".to_string();
    }
    let mut message = format!("replay file not found: {}", tried[0].display());
    if tried.len() > 1 {
        message.push_str(&format!(" (also tried: {})", tried[1].display()));
    }
    message
}

fn default_runtime_dir() -> PathBuf {
    if let Some(override_dir) =
        env::var_os("CRIMSON_RUNTIME_DIR").or_else(|| env::var_os("CRIMSON_BASE_DIR"))
    {
        return PathBuf::from(override_dir);
    }
    if let Some(base_dirs) = BaseDirs::new() {
        return base_dirs.data_dir().join("banteg").join("crimsonland");
    }
    PathBuf::from(".")
}

fn render_verify_error(err: &VerifyError) -> String {
    err.to_string()
}
