from __future__ import annotations

import subprocess
from functools import lru_cache
from pathlib import Path
from typing import TypeAlias

import msgspec

from .. import __version__
from ..replay.types import PackedPlayerInput

PROTOCOL_VERSION = 1
DEFAULT_PORT = 31993
TICK_RATE = 60
INPUT_DELAY_TICKS = 2
MAX_PLAYERS = 4
RELIABLE_RESEND_MS = 40
LINK_TIMEOUT_MS = 1000
INPUT_STALL_TIMEOUT_MS = 250
STATE_HASH_PERIOD_TICKS = 120


@lru_cache(maxsize=1)
def current_build_id() -> str:
    """Return runtime build id, preferring git commit hash over package version."""
    try:
        repo_root = Path(__file__).resolve().parents[3]
        out = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
        build = out.decode("utf-8", errors="replace").strip()
        if build:
            return str(build)
    except (OSError, subprocess.CalledProcessError):
        pass
    return str(__version__)


class Hello(msgspec.Struct, tag_field="kind", tag="hello", forbid_unknown_fields=True):
    protocol_version: int = PROTOCOL_VERSION
    build_id: str = ""
    mode_id: int = 0
    player_count: int = 1
    tick_rate: int = TICK_RATE
    input_delay_ticks: int = INPUT_DELAY_TICKS
    quest_level: str = ""
    preserve_bugs: bool = False
    host: bool = False


class Welcome(msgspec.Struct, tag_field="kind", tag="welcome", forbid_unknown_fields=True):
    accepted: bool = False
    reason: str = ""
    session_id: str = ""
    protocol_version: int = PROTOCOL_VERSION
    build_id: str = ""
    mode_id: int = 0
    player_count: int = 1
    slot_index: int = -1
    host_slot_index: int = 0
    tick_rate: int = TICK_RATE
    input_delay_ticks: int = INPUT_DELAY_TICKS
    seed: int = 0
    quest_level: str = ""
    preserve_bugs: bool = False
    started: bool = False


class LobbySlot(msgspec.Struct, forbid_unknown_fields=True):
    slot_index: int = -1
    connected: bool = False
    ready: bool = False
    is_host: bool = False
    peer_name: str = ""


class LobbyState(msgspec.Struct, tag_field="kind", tag="lobby_state", forbid_unknown_fields=True):
    session_id: str = ""
    mode_id: int = 0
    player_count: int = 1
    slots: list[LobbySlot] = msgspec.field(default_factory=list)
    all_ready: bool = False
    started: bool = False
    quest_level: str = ""


class Ready(msgspec.Struct, tag_field="kind", tag="ready", forbid_unknown_fields=True):
    slot_index: int = -1
    ready: bool = False


class MatchStart(msgspec.Struct, tag_field="kind", tag="match_start", forbid_unknown_fields=True):
    session_id: str = ""
    mode_id: int = 0
    player_count: int = 1
    seed: int = 0
    start_tick: int = 0
    quest_level: str = ""
    preserve_bugs: bool = False


class InputSample(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int = 0
    packed_input: PackedPlayerInput = msgspec.field(default_factory=list)


class InputBatch(msgspec.Struct, tag_field="kind", tag="input_batch", forbid_unknown_fields=True):
    slot_index: int = -1
    samples: list[InputSample] = msgspec.field(default_factory=list)


class TickFrame(msgspec.Struct, tag_field="kind", tag="tick_frame", forbid_unknown_fields=True):
    tick_index: int = 0
    frame_inputs: list[PackedPlayerInput] = msgspec.field(default_factory=list)
    command_hash: str = ""
    state_hash: str = ""


class PauseState(msgspec.Struct, tag_field="kind", tag="pause_state", forbid_unknown_fields=True):
    paused: bool = False
    reason: str = ""


class DesyncNotice(msgspec.Struct, tag_field="kind", tag="desync_notice", forbid_unknown_fields=True):
    tick_index: int = -1
    expected_command_hash: str = ""
    actual_command_hash: str = ""


class ResyncBegin(msgspec.Struct, tag_field="kind", tag="resync_begin", forbid_unknown_fields=True):
    stream_id: str = ""
    total_chunks: int = 0
    compressed_size: int = 0
    replay_size: int = 0
    checkpoints_size: int = 0


class ResyncChunk(msgspec.Struct, tag_field="kind", tag="resync_chunk", forbid_unknown_fields=True):
    stream_id: str = ""
    chunk_index: int = 0
    payload: bytes = b""


class ResyncCommit(msgspec.Struct, tag_field="kind", tag="resync_commit", forbid_unknown_fields=True):
    stream_id: str = ""
    tick_index: int = -1


class Disconnect(msgspec.Struct, tag_field="kind", tag="disconnect", forbid_unknown_fields=True):
    reason: str = ""


NetMessage: TypeAlias = (
    Hello
    | Welcome
    | LobbyState
    | Ready
    | MatchStart
    | TickFrame
    | PauseState
    | DesyncNotice
    | ResyncBegin
    | ResyncChunk
    | ResyncCommit
    | Disconnect
    | InputBatch
)


class Packet(msgspec.Struct, forbid_unknown_fields=True):
    seq: int = 0
    ack: int = 0
    reliable: bool = False
    message: NetMessage = msgspec.field(default_factory=PauseState)


_PACKET_DECODER = msgspec.msgpack.Decoder(type=Packet)


def encode_packet(packet: Packet) -> bytes:
    return msgspec.msgpack.encode(packet)


def decode_packet(blob: bytes) -> Packet:
    return _PACKET_DECODER.decode(blob)
