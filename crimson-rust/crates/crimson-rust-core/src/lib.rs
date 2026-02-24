#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod rand;
pub mod replay;
pub mod tables;
pub mod verify;

pub use verify::{
    verify_replay_bytes, verify_replay_file, RunResult, ScoreClaimPayload, ScoreMetric,
    VerifyError, VerifyOptions, VerifyPayload, REPLAY_VERIFY_SCORE_MISMATCH_EXIT_CODE,
};
