from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import TypeAlias

import msgspec

from .. import __version__
from ..replay.types import PackedPlayerInput

PROTOCOL_VERSION = 2
DEFAULT_PORT = 31993
TICK_RATE = 60
# LAN runs on a good network and doesn't need a large buffer; keeping this low
# reduces perceived input latency.
INPUT_DELAY_TICKS = 1
MAX_PLAYERS = 4
RELIABLE_RESEND_MS = 40
LINK_TIMEOUT_MS = 1000
INPUT_STALL_TIMEOUT_MS = 250
STATE_HASH_PERIOD_TICKS = 120


_BUILD_ID_VERSION_RE = re.compile(r"^[vV]?\d+(?:\.\d+)+[A-Za-z0-9.\-_]*$")
_BUILD_ID_GIT_HASH_RE = re.compile(r"^[0-9a-f]{7,40}$")


def build_public_version(build_id: str) -> str | None:
    """Extract a "public" version from a build id if it resembles a version string.

    Supports plain versions like "0.1.0" and build ids with local metadata like
    "0.1.0+gabcdef123456". Returns None when build_id doesn't look like a version.
    """
    raw = str(build_id).strip()
    if not raw:
        return None
    base = raw.split("+", 1)[0]
    if base.startswith(("v", "V")):
        base = base[1:]
    if _BUILD_ID_VERSION_RE.fullmatch(base) is None:
        return None
    return str(base)


def build_git_hash(build_id: str) -> str | None:
    """Extract a git hash from a build id if present."""
    raw = str(build_id).strip()
    if not raw:
        return None
    if _BUILD_ID_GIT_HASH_RE.fullmatch(raw) is not None:
        return raw.lower()
    match = re.search(r"(?:\+|\.)g([0-9a-f]{7,40})\b", raw, flags=re.IGNORECASE)
    if match is None:
        return None
    return match.group(1).lower()


def builds_compatible(peer_build_id: str, host_build_id: str) -> bool:
    """Return True when two peers should be able to talk to each other.

    LAN gameplay is lockstep and will desync on behavioral mismatches anyway; this
    is a guardrail against obvious incompatibilities while allowing:
    - release builds to join git checkouts for the same version (0.1.0 == 0.1.0+g...),
    - old hash-only build ids to interop with new "<version>+g<hash>" ids.
    """
    peer = str(peer_build_id)
    host = str(host_build_id)
    if peer == host:
        return True

    peer_hash = build_git_hash(peer)
    host_hash = build_git_hash(host)
    if peer_hash is not None and host_hash is not None and peer_hash == host_hash:
        return True

    peer_ver = build_public_version(peer)
    host_ver = build_public_version(host)
    if peer_ver is not None and host_ver is not None and peer_ver == host_ver:
        return True

    return False


@lru_cache(maxsize=1)
def current_build_id() -> str:
    """Return runtime build id.

    Format:
    - In a git checkout: "<version>+g<short_sha>"
    - In a packaged build (no git): "<version>"
    """
    version = str(__version__)
    try:
        repo_root = Path(__file__).resolve().parents[3]
        out = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
        build = out.decode("utf-8", errors="replace").strip()
        if build:
            if "+" in version:
                return f"{version}.g{build}"
            return f"{version}+g{build}"
    except (OSError, subprocess.CalledProcessError):
        pass
    return version


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


class StatusSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    """Status snapshot shipped from host to all peers for deterministic simulation.

    This intentionally mirrors the fields in `persistence.save_status.GAME_STATUS_STRUCT`
    so LAN simulation doesn't depend on local save progress.
    """

    quest_unlock_index: int = 0
    quest_unlock_index_full: int = 0
    weapon_usage_counts: list[int] = msgspec.field(default_factory=list)
    quest_play_counts: list[int] = msgspec.field(default_factory=list)
    mode_play_survival: int = 0
    mode_play_rush: int = 0
    mode_play_typo: int = 0
    mode_play_other: int = 0
    game_sequence_id: int = 0
    unknown_tail: bytes = b""


class MatchStart(msgspec.Struct, tag_field="kind", tag="match_start", forbid_unknown_fields=True):
    session_id: str = ""
    mode_id: int = 0
    player_count: int = 1
    seed: int = 0
    start_tick: int = 0
    quest_level: str = ""
    preserve_bugs: bool = False
    status_snapshot: StatusSnapshot | None = None
    status_hash: str = ""


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


class DebugLogBatch(msgspec.Struct, tag_field="kind", tag="debug_log_batch", forbid_unknown_fields=True):
    """Client-to-host debug log forwarding payload (best-effort)."""

    slot_index: int = -1
    lines: list[str] = msgspec.field(default_factory=list)


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
    | DebugLogBatch
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
