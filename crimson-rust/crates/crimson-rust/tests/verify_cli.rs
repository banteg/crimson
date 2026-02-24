use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_crimson-rust")
}

fn acceptance_replay_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tests/fixtures/replays/survival_20260224_041009_score76661.crd")
}

fn build_minimal_replay_bytes(game_mode_id: i64) -> Vec<u8> {
    let replay_obj = json!({
        "header": {
            "game_mode_id": game_mode_id,
            "seed": 0xBEEF,
            "replay_format_version": 4,
            "quest_level": "",
            "bootstrap_kind": "none",
            "bootstrap_seed": 0,
            "game_version": "test",
            "tick_rate": 60,
            "difficulty_level": 0,
            "hardcore": false,
            "preserve_bugs": false,
            "detail_preset": 5,
            "fx_toggle": 0,
            "world_size": 1024.0,
            "player_count": 1,
            "status": {
                "quest_unlock_index": 0,
                "quest_unlock_index_full": 0,
                "weapon_usage_counts": vec![0; 53],
            },
            "input_quantization": "raw",
        },
        "inputs": [],
        "events": [],
    });
    rmp_serde::to_vec(&replay_obj).expect("minimal replay msgpack should encode")
}

#[test]
fn verify_json_success_for_acceptance_replay() {
    let fixture_path = acceptance_replay_fixture();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let replay_path = std::env::temp_dir().join(format!("crimson_rust_acceptance_{unique}.crd"));
    fs::copy(&fixture_path, &replay_path).expect("fixture replay should copy to temp path");

    let output = Command::new(cli_bin())
        .arg("verify")
        .arg(&replay_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("cli invocation should succeed");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let payload: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("json output should parse");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["run_result"]["game_mode_id"], 1);
    assert_eq!(payload["run_result"]["tick_rate"], 60);
    assert_eq!(payload["run_result"]["ticks"], 25_803);
    assert!(
        payload["run_result"]["elapsed_ms"]
            .as_i64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        payload["run_result"]["score_xp"]
            .as_i64()
            .unwrap_or_default()
            >= 0
    );
}

#[test]
fn verify_infers_submitted_score_from_filename_and_returns_mismatch() {
    let replay_path = acceptance_replay_fixture();
    let output = Command::new(cli_bin())
        .arg("verify")
        .arg(&replay_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("cli invocation should succeed");

    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let payload: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("json output should parse");
    assert_eq!(payload["status"], "score_mismatch");
    assert_eq!(payload["score_claim"]["submitted_score"], 76_661);
    assert_eq!(payload["score_claim"]["metric"], "score_xp");
    assert_eq!(payload["score_claim"]["match"], false);
}

#[test]
fn verify_score_mismatch_returns_exit_code_three() {
    let replay_path = acceptance_replay_fixture();
    let output = Command::new(cli_bin())
        .arg("verify")
        .arg(&replay_path)
        .arg("--format")
        .arg("json")
        .arg("--submitted-score")
        .arg("1")
        .output()
        .expect("cli invocation should succeed");

    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let payload: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("json output should parse");
    assert_eq!(payload["status"], "score_mismatch");
    assert_eq!(payload["score_claim"]["metric"], "score_xp");
    assert_eq!(payload["score_claim"]["match"], false);
}

#[test]
fn verify_unsupported_scope_returns_exit_code_one_with_reason() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let replay_path = std::env::temp_dir().join(format!("crimson_rust_unsupported_{unique}.crd"));
    fs::write(&replay_path, build_minimal_replay_bytes(2)).expect("should write temp replay");

    let output = Command::new(cli_bin())
        .arg("verify")
        .arg(&replay_path)
        .output()
        .expect("cli invocation should succeed");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(
        stderr.contains("supports survival only"),
        "unexpected stderr: {stderr}"
    );
}
