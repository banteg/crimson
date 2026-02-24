use std::fs;
use std::path::PathBuf;

use crimson_rust_core::replay::WEAPON_USAGE_COUNT;
use crimson_rust_core::{verify_replay_bytes, ScoreMetric, VerifyOptions};
use serde_json::json;

fn acceptance_replay_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tests/fixtures/replays/survival_20260224_041009_score76661.crd")
}

fn acceptance_python_json_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tests/fixtures/replays/survival_20260224_041009_score76661.verify.python.json")
}

fn build_minimal_replay_bytes(
    game_mode_id: i64,
    player_count: i64,
    preserve_bugs: bool,
) -> Vec<u8> {
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
            "preserve_bugs": preserve_bugs,
            "detail_preset": 5,
            "fx_toggle": 0,
            "world_size": 1024.0,
            "player_count": player_count,
            "status": {
                "quest_unlock_index": 0,
                "quest_unlock_index_full": 0,
                "weapon_usage_counts": vec![0; WEAPON_USAGE_COUNT],
            },
            "input_quantization": "raw",
        },
        "inputs": [],
        "events": [],
    });

    rmp_serde::to_vec(&replay_obj).expect("minimal replay msgpack should encode")
}

#[test]
fn acceptance_replay_verify_is_deterministic_and_structural() {
    let replay_bytes = fs::read(acceptance_replay_fixture()).expect("fixture replay should exist");
    let payload0 = verify_replay_bytes(&replay_bytes, VerifyOptions::default())
        .expect("acceptance replay should verify");
    let payload1 = verify_replay_bytes(&replay_bytes, VerifyOptions::default())
        .expect("acceptance replay should verify");

    assert_eq!(payload0, payload1);
    assert_eq!(payload0.schema_version, 1);
    assert_eq!(payload0.status, "ok");
    assert_eq!(
        payload0.replay_sha256,
        "1cb9ec12b25b0a5b3529689751ef1f5a5707cbd90b5657e0e74837e55a1bf790"
    );
    assert_eq!(payload0.run_result.game_mode_id, 1);
    assert_eq!(payload0.run_result.tick_rate, 60);
    assert_eq!(payload0.run_result.ticks, 25_803);
    assert!(payload0.run_result.elapsed_ms > 0);
    assert!(payload0.run_result.score_xp >= 0);
    assert!(payload0.run_result.creature_kill_count >= 0);
    assert!(payload0.run_result.most_used_weapon_id >= 1);
    assert!(payload0.run_result.shots_fired >= 0);
    assert!(payload0.run_result.shots_hit >= 0);
    assert!(payload0.run_result.rng_state > 0);
    assert!(payload0.score_claim.is_none());
}

#[test]
fn acceptance_replay_json_schema_matches_python_fixture_shape() {
    let replay_bytes = fs::read(acceptance_replay_fixture()).expect("fixture replay should exist");
    let payload = verify_replay_bytes(
        &replay_bytes,
        VerifyOptions {
            submitted_score: None,
            score_metric: ScoreMetric::Auto,
            replay_label: Some(
                "tests/fixtures/replays/survival_20260224_041009_score76661.crd".to_string(),
            ),
        },
    )
    .expect("acceptance replay should verify");
    let rust_payload_json =
        serde_json::to_value(payload).expect("rust verify payload should serialize to json value");

    let expected_json = fs::read_to_string(acceptance_python_json_fixture())
        .expect("python json fixture should exist");
    let expected_payload_json: serde_json::Value =
        serde_json::from_str(expected_json.trim()).expect("python json fixture should parse");

    let rust_obj = rust_payload_json
        .as_object()
        .expect("rust payload should be an object");
    let expected_obj = expected_payload_json
        .as_object()
        .expect("python payload should be an object");
    let mut rust_keys = rust_obj.keys().cloned().collect::<Vec<_>>();
    let mut expected_keys = expected_obj.keys().cloned().collect::<Vec<_>>();
    rust_keys.sort();
    expected_keys.sort();
    assert_eq!(rust_keys, expected_keys);
    assert!(
        rust_payload_json != expected_payload_json,
        "isolated rust verifier should not delegate to python payload generation"
    );
}

#[test]
fn acceptance_replay_score_claim_mismatch_sets_status_and_claim_payload() {
    let replay_bytes = fs::read(acceptance_replay_fixture()).expect("fixture replay should exist");
    let payload = verify_replay_bytes(
        &replay_bytes,
        VerifyOptions {
            submitted_score: Some(1),
            score_metric: ScoreMetric::Auto,
            replay_label: None,
        },
    )
    .expect("acceptance replay should verify");

    assert_eq!(payload.status, "score_mismatch");
    let claim = payload
        .score_claim
        .expect("score claim payload should be present");
    assert_eq!(claim.metric, "score_xp");
    assert_eq!(claim.submitted_score, 1);
    assert!(claim.simulated_value >= 0);
    assert!(!claim.match_ok);
}

#[test]
fn unsupported_scope_errors_are_explicit() {
    let rush_bytes = build_minimal_replay_bytes(2, 1, false);
    let err = verify_replay_bytes(&rush_bytes, VerifyOptions::default())
        .expect_err("rush replay should be rejected");
    assert!(
        err.to_string().contains("supports survival only"),
        "unexpected error: {err}"
    );

    let mp_bytes = build_minimal_replay_bytes(1, 2, false);
    let err = verify_replay_bytes(&mp_bytes, VerifyOptions::default())
        .expect_err("multiplayer replay should be rejected");
    assert!(
        err.to_string().contains("supports 1P only"),
        "unexpected error: {err}"
    );

    let preserve_bytes = build_minimal_replay_bytes(1, 1, true);
    let err = verify_replay_bytes(&preserve_bytes, VerifyOptions::default())
        .expect_err("preserve_bugs replay should be rejected");
    assert!(
        err.to_string().contains("preserve_bugs=false only"),
        "unexpected error: {err}"
    );
}
