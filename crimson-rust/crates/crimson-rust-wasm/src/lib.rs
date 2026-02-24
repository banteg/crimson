#![forbid(unsafe_code)]

use crimson_rust_core::{verify_replay_bytes, VerifyOptions};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = verifyReplayBytes)]
pub fn verify_replay_bytes_wasm(replay_bytes: &[u8], options_json: Option<String>) -> String {
    match verify_replay_bytes_json(replay_bytes, options_json.as_deref()) {
        Ok(payload_json) => payload_json,
        Err(err_json) => err_json,
    }
}

pub fn verify_replay_bytes_json(
    replay_bytes: &[u8],
    options_json: Option<&str>,
) -> Result<String, String> {
    let options = match options_json {
        Some(raw) if !raw.trim().is_empty() => serde_json::from_str::<VerifyOptions>(raw)
            .map_err(|err| error_payload(&format!("invalid options_json: {err}")))?,
        _ => VerifyOptions::default(),
    };

    let payload = verify_replay_bytes(replay_bytes, options)
        .map_err(|err| error_payload(&format!("replay verification failed: {err}")))?;

    serde_json::to_string(&payload)
        .map_err(|err| error_payload(&format!("failed to serialize verify payload: {err}")))
}

fn error_payload(message: &str) -> String {
    serde_json::json!({
        "schema_version": 1,
        "status": "error",
        "error": message,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::Value;

    use super::verify_replay_bytes_json;

    fn acceptance_replay_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("tests/fixtures/replays/survival_20260224_041009_score76661.crd")
    }

    #[test]
    fn wasm_smoke_acceptance_payload_matches_expected_run_result() {
        let replay_path = acceptance_replay_fixture();
        let replay_bytes = fs::read(&replay_path).expect("fixture replay should exist");
        let payload_json = verify_replay_bytes_json(&replay_bytes, None)
            .expect("verify_replay_bytes_json should succeed");
        let payload: Value =
            serde_json::from_str(&payload_json).expect("payload should be valid json");

        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["run_result"]["ticks"], 25_803);
        assert_eq!(payload["run_result"]["elapsed_ms"], 398_030);
        assert_eq!(payload["run_result"]["score_xp"], 76_661);
        assert_eq!(payload["run_result"]["creature_kill_count"], 951);
        assert_eq!(payload["run_result"]["most_used_weapon_id"], 14);
        assert_eq!(payload["run_result"]["shots_fired"], 4_566);
        assert_eq!(payload["run_result"]["shots_hit"], 1_467);
        assert_eq!(payload["run_result"]["rng_state"], 2_889_720_653_u64);
    }
}
