use std::io::Read;

use flate2::read::GzDecoder;
use rmpv::Value;
use thiserror::Error;

pub const REPLAY_FORMAT_VERSION: i64 = 4;
pub const WEAPON_USAGE_COUNT: usize = 53;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const DEFAULT_MAX_REPLAY_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapKind {
    None,
    TerrainV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputQuantization {
    Raw,
    F32,
}

#[derive(Debug, Clone)]
pub struct ReplayStatusSnapshot {
    pub quest_unlock_index: i64,
    pub quest_unlock_index_full: i64,
    pub weapon_usage_counts: Vec<i64>,
}

#[derive(Debug, Clone)]
pub struct ReplayHeader {
    pub game_mode_id: i64,
    pub seed: i64,
    pub replay_format_version: i64,
    pub quest_level: String,
    pub bootstrap_kind: BootstrapKind,
    pub bootstrap_seed: i64,
    pub game_version: String,
    pub tick_rate: i64,
    pub difficulty_level: i64,
    pub hardcore: bool,
    pub preserve_bugs: bool,
    pub detail_preset: i64,
    pub fx_toggle: i64,
    pub world_size: f64,
    pub player_count: i64,
    pub status: ReplayStatusSnapshot,
    pub input_quantization: InputQuantization,
}

#[derive(Debug, Clone)]
pub struct PackedPlayerInput {
    pub move_x: f64,
    pub move_y: f64,
    pub aim_x: f64,
    pub aim_y: f64,
    pub flags: i64,
}

#[derive(Debug, Clone)]
pub struct PerkPickEvent {
    pub tick_index: i64,
    pub player_index: i64,
    pub choice_index: i64,
}

#[derive(Debug, Clone)]
pub struct PerkMenuOpenEvent {
    pub tick_index: i64,
    pub player_index: i64,
}

#[derive(Debug, Clone)]
pub struct UnknownEvent {
    pub tick_index: i64,
    pub kind: String,
    pub payload: Vec<Value>,
}

#[derive(Debug, Clone)]
pub enum ReplayEvent {
    PerkPick(PerkPickEvent),
    PerkMenuOpen(PerkMenuOpenEvent),
    Unknown(UnknownEvent),
}

impl ReplayEvent {
    pub fn tick_index(&self) -> i64 {
        match self {
            Self::PerkPick(ev) => ev.tick_index,
            Self::PerkMenuOpen(ev) => ev.tick_index,
            Self::Unknown(ev) => ev.tick_index,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Replay {
    pub header: ReplayHeader,
    pub inputs: Vec<Vec<PackedPlayerInput>>,
    pub events: Vec<ReplayEvent>,
}

#[derive(Debug, Error)]
pub enum ReplayCodecError {
    #[error("invalid replay gzip payload")]
    InvalidGzipPayload,
    #[error("replay payload too large (> {0} bytes)")]
    ReplayPayloadTooLarge(usize),
    #[error("legacy JSON replay format is unsupported; regenerate the replay")]
    LegacyJsonUnsupported,
    #[error("invalid replay msgpack payload")]
    InvalidReplayMsgpackPayload,
    #[error("missing replay field: {0}")]
    MissingField(&'static str),
    #[error("invalid replay field: {0}")]
    InvalidField(&'static str),
    #[error("unsupported replay format version: {0}")]
    UnsupportedReplayFormatVersion(i64),
    #[error("replay header player_count must be positive, got {0}")]
    InvalidPlayerCount(i64),
    #[error("unknown input_quantization: {0:?}")]
    UnknownInputQuantization(String),
    #[error("unknown bootstrap_kind: {0:?}")]
    UnknownBootstrapKind(String),
    #[error("replay header status.weapon_usage_counts must have {WEAPON_USAGE_COUNT} entries")]
    InvalidWeaponUsageCounts,
    #[error("replay tick {tick_idx} has {actual} players, expected {expected}")]
    TickPlayerCountMismatch {
        tick_idx: usize,
        actual: usize,
        expected: usize,
    },
    #[error(
        "perk_pick must have non-negative player/choice indexes: {player_index}, {choice_index}"
    )]
    InvalidPerkPick {
        player_index: i64,
        choice_index: i64,
    },
    #[error("perk_menu_open must have non-negative player index: {player_index}")]
    InvalidPerkMenuOpen { player_index: i64 },
    #[error("replay event tick_index must be non-negative, got {0}")]
    InvalidEventTickIndex(i64),
    #[error("replay event tick_index out of bounds: {tick} > {max}")]
    EventTickOutOfBounds { tick: i64, max: usize },
}

pub fn load_replay(data: &[u8]) -> Result<Replay, ReplayCodecError> {
    let max_payload_bytes = DEFAULT_MAX_REPLAY_PAYLOAD_BYTES;
    let mut payload = if is_gzip(data) {
        decompress_gzip_replay(data, max_payload_bytes)?
    } else {
        data.to_vec()
    };
    if payload.len() > max_payload_bytes {
        return Err(ReplayCodecError::ReplayPayloadTooLarge(max_payload_bytes));
    }

    if payload
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .next()
        .is_some_and(|b| *b == b'{' || *b == b'[')
    {
        return Err(ReplayCodecError::LegacyJsonUnsupported);
    }

    let value: Value = rmp_serde::from_slice(&payload)
        .map_err(|_| ReplayCodecError::InvalidReplayMsgpackPayload)?;
    payload.clear();

    let map = as_map(&value).ok_or(ReplayCodecError::InvalidReplayMsgpackPayload)?;
    let header = parse_header(required_field(map, "header")?)?;
    let inputs = parse_inputs(required_field(map, "inputs")?, &header)?;
    let events = parse_events(optional_field(map, "events"), inputs.len())?;

    Ok(Replay {
        header,
        inputs,
        events,
    })
}

fn parse_header(value: &Value) -> Result<ReplayHeader, ReplayCodecError> {
    let map = as_map(value).ok_or(ReplayCodecError::InvalidField("header"))?;

    let replay_format_version = int_field(map, "replay_format_version")?;
    if replay_format_version != REPLAY_FORMAT_VERSION {
        return Err(ReplayCodecError::UnsupportedReplayFormatVersion(
            replay_format_version,
        ));
    }

    let player_count = int_field_with_default(map, "player_count", 1)?;
    if player_count <= 0 {
        return Err(ReplayCodecError::InvalidPlayerCount(player_count));
    }

    let input_quantization =
        match str_field_with_default(map, "input_quantization", "raw")?.as_str() {
            "raw" => InputQuantization::Raw,
            "f32" => InputQuantization::F32,
            other => {
                return Err(ReplayCodecError::UnknownInputQuantization(
                    other.to_string(),
                ))
            }
        };

    let bootstrap_kind = match str_field_with_default(map, "bootstrap_kind", "none")?.as_str() {
        "none" => BootstrapKind::None,
        "terrain_v1" => BootstrapKind::TerrainV1,
        other => return Err(ReplayCodecError::UnknownBootstrapKind(other.to_string())),
    };

    let status_value = optional_field(map, "status")
        .cloned()
        .unwrap_or(Value::Map(vec![]));
    let status_map =
        as_map(&status_value).ok_or(ReplayCodecError::InvalidField("header.status"))?;

    let usage_raw = array_field(status_map, "weapon_usage_counts")?;
    if usage_raw.len() != WEAPON_USAGE_COUNT {
        return Err(ReplayCodecError::InvalidWeaponUsageCounts);
    }
    let mut weapon_usage_counts = Vec::with_capacity(usage_raw.len());
    for entry in usage_raw {
        weapon_usage_counts.push(value_to_i64(entry).ok_or(ReplayCodecError::InvalidField(
            "header.status.weapon_usage_counts",
        ))?);
    }

    Ok(ReplayHeader {
        game_mode_id: int_field(map, "game_mode_id")?,
        seed: int_field(map, "seed")?,
        replay_format_version,
        quest_level: str_field_with_default(map, "quest_level", "")?,
        bootstrap_kind,
        bootstrap_seed: int_field_with_default(map, "bootstrap_seed", 0)?,
        game_version: str_field_with_default(map, "game_version", "")?,
        tick_rate: int_field_with_default(map, "tick_rate", 60)?,
        difficulty_level: int_field_with_default(map, "difficulty_level", 0)?,
        hardcore: bool_field_with_default(map, "hardcore", false)?,
        preserve_bugs: bool_field_with_default(map, "preserve_bugs", false)?,
        detail_preset: int_field_with_default(map, "detail_preset", 5)?,
        fx_toggle: int_field_with_default(map, "fx_toggle", 0)?,
        world_size: float_field_with_default(map, "world_size", 1024.0)?,
        player_count,
        status: ReplayStatusSnapshot {
            quest_unlock_index: int_field_with_default(status_map, "quest_unlock_index", 0)?,
            quest_unlock_index_full: int_field_with_default(
                status_map,
                "quest_unlock_index_full",
                0,
            )?,
            weapon_usage_counts,
        },
        input_quantization,
    })
}

fn parse_inputs(
    value: &Value,
    header: &ReplayHeader,
) -> Result<Vec<Vec<PackedPlayerInput>>, ReplayCodecError> {
    let ticks = as_array(value).ok_or(ReplayCodecError::InvalidField("inputs"))?;
    let expected_players = usize::try_from(header.player_count)
        .map_err(|_| ReplayCodecError::InvalidPlayerCount(header.player_count))?;

    let mut inputs = Vec::with_capacity(ticks.len());
    for (tick_idx, tick_value) in ticks.iter().enumerate() {
        let tick_entries =
            as_array(tick_value).ok_or(ReplayCodecError::InvalidField("inputs[tick]"))?;
        if tick_entries.len() != expected_players {
            return Err(ReplayCodecError::TickPlayerCountMismatch {
                tick_idx,
                actual: tick_entries.len(),
                expected: expected_players,
            });
        }
        let mut packed_tick = Vec::with_capacity(tick_entries.len());
        for player_value in tick_entries {
            packed_tick.push(parse_packed_player_input(
                player_value,
                header.input_quantization,
            )?);
        }
        inputs.push(packed_tick);
    }

    Ok(inputs)
}

fn parse_packed_player_input(
    value: &Value,
    quant: InputQuantization,
) -> Result<PackedPlayerInput, ReplayCodecError> {
    let mut move_x;
    let mut move_y;
    let mut aim_x;
    let mut aim_y;
    let flags;

    if let Some(array) = as_array(value) {
        if array.len() < 5 {
            return Err(ReplayCodecError::InvalidField("inputs[player]"));
        }
        move_x = value_to_f64(&array[0])
            .ok_or(ReplayCodecError::InvalidField("inputs[player].move_x"))?;
        move_y = value_to_f64(&array[1])
            .ok_or(ReplayCodecError::InvalidField("inputs[player].move_y"))?;
        aim_x = value_to_f64(&array[2])
            .ok_or(ReplayCodecError::InvalidField("inputs[player].aim_x"))?;
        aim_y = value_to_f64(&array[3])
            .ok_or(ReplayCodecError::InvalidField("inputs[player].aim_y"))?;
        flags = value_to_i64(&array[4])
            .ok_or(ReplayCodecError::InvalidField("inputs[player].flags"))?;
    } else {
        let map = as_map(value).ok_or(ReplayCodecError::InvalidField("inputs[player]"))?;
        move_x = float_field(map, "move_x")?;
        move_y = float_field(map, "move_y")?;
        aim_x = float_field(map, "aim_x")?;
        aim_y = float_field(map, "aim_y")?;
        flags = int_field(map, "flags")?;
    }

    if quant == InputQuantization::F32 {
        move_x = quantize_f32(move_x);
        move_y = quantize_f32(move_y);
        aim_x = quantize_f32(aim_x);
        aim_y = quantize_f32(aim_y);
    }

    Ok(PackedPlayerInput {
        move_x,
        move_y,
        aim_x,
        aim_y,
        flags,
    })
}

fn parse_events(
    value: Option<&Value>,
    input_len: usize,
) -> Result<Vec<ReplayEvent>, ReplayCodecError> {
    let Some(value) = value else {
        return Ok(vec![]);
    };

    let entries = as_array(value).ok_or(ReplayCodecError::InvalidField("events"))?;
    let mut out = Vec::with_capacity(entries.len());

    for entry in entries {
        let wire = parse_event_wire(entry)?;
        let event = if wire.kind == "perk_pick" {
            if wire.player_index < 0 || wire.choice_index < 0 {
                return Err(ReplayCodecError::InvalidPerkPick {
                    player_index: wire.player_index,
                    choice_index: wire.choice_index,
                });
            }
            if !wire.payload.is_empty() {
                return Err(ReplayCodecError::InvalidField("events.perk_pick.payload"));
            }
            ReplayEvent::PerkPick(PerkPickEvent {
                tick_index: wire.tick_index,
                player_index: wire.player_index,
                choice_index: wire.choice_index,
            })
        } else if wire.kind == "perk_menu_open" {
            if wire.player_index < 0 {
                return Err(ReplayCodecError::InvalidPerkMenuOpen {
                    player_index: wire.player_index,
                });
            }
            if !wire.payload.is_empty() {
                return Err(ReplayCodecError::InvalidField(
                    "events.perk_menu_open.payload",
                ));
            }
            ReplayEvent::PerkMenuOpen(PerkMenuOpenEvent {
                tick_index: wire.tick_index,
                player_index: wire.player_index,
            })
        } else {
            ReplayEvent::Unknown(UnknownEvent {
                tick_index: wire.tick_index,
                kind: wire.kind,
                payload: wire.payload,
            })
        };

        let tick_index = event.tick_index();
        if tick_index < 0 {
            return Err(ReplayCodecError::InvalidEventTickIndex(tick_index));
        }
        if usize::try_from(tick_index)
            .ok()
            .is_none_or(|tick| tick > input_len)
        {
            return Err(ReplayCodecError::EventTickOutOfBounds {
                tick: tick_index,
                max: input_len,
            });
        }

        out.push(event);
    }

    Ok(out)
}

struct EventWire {
    tick_index: i64,
    kind: String,
    player_index: i64,
    choice_index: i64,
    payload: Vec<Value>,
}

fn parse_event_wire(value: &Value) -> Result<EventWire, ReplayCodecError> {
    if let Some(array) = as_array(value) {
        if array.len() < 2 {
            return Err(ReplayCodecError::InvalidField("events[]"));
        }
        let tick_index =
            value_to_i64(&array[0]).ok_or(ReplayCodecError::InvalidField("events[].tick_index"))?;
        let kind =
            value_to_string(&array[1]).ok_or(ReplayCodecError::InvalidField("events[].kind"))?;
        let player_index = array.get(2).and_then(value_to_i64).unwrap_or(-1);
        let choice_index = array.get(3).and_then(value_to_i64).unwrap_or(-1);
        let payload = array
            .get(4)
            .and_then(as_array)
            .map(|vals| vals.to_vec())
            .unwrap_or_default();
        return Ok(EventWire {
            tick_index,
            kind,
            player_index,
            choice_index,
            payload,
        });
    }

    let map = as_map(value).ok_or(ReplayCodecError::InvalidField("events[]"))?;
    let payload = optional_field(map, "payload")
        .and_then(as_array)
        .map(|vals| vals.to_vec())
        .unwrap_or_default();

    Ok(EventWire {
        tick_index: int_field(map, "tick_index")?,
        kind: str_field(map, "kind")?,
        player_index: int_field_with_default(map, "player_index", -1)?,
        choice_index: int_field_with_default(map, "choice_index", -1)?,
        payload,
    })
}

fn is_gzip(data: &[u8]) -> bool {
    data.starts_with(&GZIP_MAGIC)
}

fn decompress_gzip_replay(
    data: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>, ReplayCodecError> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::with_capacity(max_output_bytes.min(4096));
    decoder
        .by_ref()
        .take(u64::try_from(max_output_bytes + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut out)
        .map_err(|_| ReplayCodecError::InvalidGzipPayload)?;
    if out.len() > max_output_bytes {
        return Err(ReplayCodecError::ReplayPayloadTooLarge(max_output_bytes));
    }
    Ok(out)
}

fn quantize_f32(value: f64) -> f64 {
    f64::from(value as f32)
}

fn as_map(value: &Value) -> Option<&[(Value, Value)]> {
    match value {
        Value::Map(map) => Some(map.as_slice()),
        _ => None,
    }
}

fn as_array(value: &Value) -> Option<&[Value]> {
    match value {
        Value::Array(entries) => Some(entries.as_slice()),
        _ => None,
    }
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| (k.as_str() == Some(key)).then_some(v))
}

fn required_field<'a>(
    map: &'a [(Value, Value)],
    key: &'static str,
) -> Result<&'a Value, ReplayCodecError> {
    map_get(map, key).ok_or(ReplayCodecError::MissingField(key))
}

fn optional_field<'a>(map: &'a [(Value, Value)], key: &'static str) -> Option<&'a Value> {
    map_get(map, key)
}

fn int_field(map: &[(Value, Value)], key: &'static str) -> Result<i64, ReplayCodecError> {
    value_to_i64(required_field(map, key)?).ok_or(ReplayCodecError::InvalidField(key))
}

fn int_field_with_default(
    map: &[(Value, Value)],
    key: &'static str,
    default: i64,
) -> Result<i64, ReplayCodecError> {
    match optional_field(map, key) {
        Some(value) => value_to_i64(value).ok_or(ReplayCodecError::InvalidField(key)),
        None => Ok(default),
    }
}

fn float_field(map: &[(Value, Value)], key: &'static str) -> Result<f64, ReplayCodecError> {
    value_to_f64(required_field(map, key)?).ok_or(ReplayCodecError::InvalidField(key))
}

fn float_field_with_default(
    map: &[(Value, Value)],
    key: &'static str,
    default: f64,
) -> Result<f64, ReplayCodecError> {
    match optional_field(map, key) {
        Some(value) => value_to_f64(value).ok_or(ReplayCodecError::InvalidField(key)),
        None => Ok(default),
    }
}

fn str_field(map: &[(Value, Value)], key: &'static str) -> Result<String, ReplayCodecError> {
    value_to_string(required_field(map, key)?).ok_or(ReplayCodecError::InvalidField(key))
}

fn str_field_with_default(
    map: &[(Value, Value)],
    key: &'static str,
    default: &str,
) -> Result<String, ReplayCodecError> {
    match optional_field(map, key) {
        Some(value) => value_to_string(value).ok_or(ReplayCodecError::InvalidField(key)),
        None => Ok(default.to_string()),
    }
}

fn array_field<'a>(
    map: &'a [(Value, Value)],
    key: &'static str,
) -> Result<&'a [Value], ReplayCodecError> {
    as_array(required_field(map, key)?).ok_or(ReplayCodecError::InvalidField(key))
}

fn bool_field_with_default(
    map: &[(Value, Value)],
    key: &'static str,
    default: bool,
) -> Result<bool, ReplayCodecError> {
    match optional_field(map, key) {
        Some(value) => value_to_bool(value).ok_or(ReplayCodecError::InvalidField(key)),
        None => Ok(default),
    }
}

fn value_to_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(v) => v
            .as_i64()
            .or_else(|| v.as_u64().and_then(|x| i64::try_from(x).ok())),
        Value::F32(v) => Some(*v as i64),
        Value::F64(v) => Some(*v as i64),
        Value::Boolean(v) => Some(if *v { 1 } else { 0 }),
        _ => None,
    }
}

fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::F32(v) => Some(f64::from(*v)),
        Value::F64(v) => Some(*v),
        Value::Integer(v) => {
            if let Some(i) = v.as_i64() {
                Some(i as f64)
            } else {
                v.as_u64().map(|u| u as f64)
            }
        }
        Value::Boolean(v) => Some(if *v { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    value.as_str().map(ToString::to_string)
}

fn value_to_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Boolean(v) => Some(*v),
        Value::Integer(v) => v.as_i64().map(|i| i != 0),
        _ => None,
    }
}
