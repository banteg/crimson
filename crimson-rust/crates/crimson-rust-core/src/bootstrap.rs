#![forbid(unsafe_code)]

use crate::rand::CrtRand;
use crate::replay::{BootstrapKind, ReplayHeader};

pub const BOOTSTRAP_KIND_NONE: &str = "none";
pub const BOOTSTRAP_KIND_TERRAIN_V1: &str = "terrain_v1";

const TERRAIN_DEFAULT_IDS: (i64, i64, i64) = (0, 1, 0);
const TERRAIN_UNLOCK_RULES: &[(i64, (i64, i64, i64))] =
    &[(0x28, (6, 7, 6)), (0x1E, (4, 5, 4)), (0x14, (2, 3, 2))];

const TERRAIN_DENSITY_BASE: i64 = 800;
const TERRAIN_DENSITY_OVERLAY: i64 = 0x23;
const TERRAIN_DENSITY_DETAIL: i64 = 0x0F;
const TERRAIN_DENSITY_SHIFT: i64 = 19;
const TERRAIN_RAND_DRAWS_PER_STAMP: i64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerrainBootstrapResult {
    pub kind: String,
    pub seed_before: u32,
    pub seed_after: u32,
    pub terrain_ids: (i64, i64, i64),
    pub terrain_seed: u32,
    pub selection_draws: i64,
    pub stamping_draws: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedReplayBootstrap {
    pub terrain: TerrainBootstrapResult,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayBootstrapError {
    #[error("unsupported replay bootstrap_kind={0:?}")]
    UnsupportedBootstrapKind(String),
    #[error("bootstrap seed mismatch: header.seed={header_seed} != computed={computed}")]
    BootstrapSeedMismatch { header_seed: i64, computed: u32 },
}

pub fn choose_terrain_ids(quest_unlock_index: i64, rng: &mut CrtRand) -> ((i64, i64, i64), i64) {
    let mut draws = 0_i64;
    for (threshold, ids) in TERRAIN_UNLOCK_RULES {
        if quest_unlock_index < *threshold {
            continue;
        }
        draws += 1;
        if (rng.rand() & 7) == 3 {
            return (*ids, draws);
        }
    }
    (TERRAIN_DEFAULT_IDS, draws)
}

pub fn terrain_stamping_draws(width: i64, height: i64, layers: i64) -> i64 {
    let w = width.max(0);
    let h = height.max(0);
    let layers = layers.clamp(0, 3);
    let area = w.saturating_mul(h);

    let mut stamps = 0_i64;
    if layers >= 1 {
        stamps += (area.saturating_mul(TERRAIN_DENSITY_BASE)) >> TERRAIN_DENSITY_SHIFT;
    }
    if layers >= 2 {
        stamps += (area.saturating_mul(TERRAIN_DENSITY_OVERLAY)) >> TERRAIN_DENSITY_SHIFT;
    }
    if layers >= 3 {
        stamps += (area.saturating_mul(TERRAIN_DENSITY_DETAIL)) >> TERRAIN_DENSITY_SHIFT;
    }
    stamps.saturating_mul(TERRAIN_RAND_DRAWS_PER_STAMP)
}

pub fn run_terrain_bootstrap(
    rng: &mut CrtRand,
    quest_unlock_index: i64,
    width: i64,
    height: i64,
    layers: i64,
) -> TerrainBootstrapResult {
    let seed_before = rng.state();
    let (terrain_ids, selection_draws) = choose_terrain_ids(quest_unlock_index, rng);

    let terrain_seed = rng.state();
    let stamping_draws = terrain_stamping_draws(width, height, layers);
    for _ in 0..stamping_draws.max(0) {
        rng.rand();
    }

    TerrainBootstrapResult {
        kind: BOOTSTRAP_KIND_TERRAIN_V1.to_string(),
        seed_before,
        seed_after: rng.state(),
        terrain_ids,
        terrain_seed,
        selection_draws,
        stamping_draws,
    }
}

pub fn apply_replay_bootstrap(
    header: &ReplayHeader,
    rng: &mut CrtRand,
    world_size: f64,
    strict: bool,
) -> Result<Option<AppliedReplayBootstrap>, ReplayBootstrapError> {
    match header.bootstrap_kind {
        BootstrapKind::None => {
            rng.srand(header.seed as u32);
            Ok(None)
        }
        BootstrapKind::TerrainV1 => {
            let width = world_size.max(1.0) as i64;
            let height = width;
            rng.srand(header.bootstrap_seed as u32);
            let terrain =
                run_terrain_bootstrap(rng, header.status.quest_unlock_index, width, height, 3);
            if strict && (header.seed as u32) != terrain.seed_after {
                return Err(ReplayBootstrapError::BootstrapSeedMismatch {
                    header_seed: header.seed,
                    computed: terrain.seed_after,
                });
            }
            Ok(Some(AppliedReplayBootstrap { terrain }))
        }
    }
}
