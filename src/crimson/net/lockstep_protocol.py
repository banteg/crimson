from __future__ import annotations

import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

import msgspec

from .. import __version__
from ..game_modes import GameMode
from ..msgspec_types import NonNegativeInt, PlayerCount, PositiveInt, SignedIndex
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..replay.types import PackedPlayerInput
from ..sim.input_providers import GameCommand
from .schema_shared import PacketHeader, SlotState

PROTOCOL_VERSION = 6
DEFAULT_PORT = 31993
TICK_RATE = 60
# LAN runs on a good network and doesn't need a large buffer; keeping this low
# reduces perceived input latency.
INPUT_DELAY_TICKS = 1
MAX_PLAYERS = 4
RELIABLE_RESEND_MS = 40
LINK_TIMEOUT_MS = 1000
INPUT_STALL_TIMEOUT_MS = 250
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
    if peer_hash is not None and host_hash is not None:
        # Lockstep sessions are sensitive to tiny behavioral drift. If both peers
        # report git hashes, require an exact hash match.
        return peer_hash == host_hash

    peer_ver = build_public_version(peer)
    host_ver = build_public_version(host)
    return bool(peer_ver is not None and host_ver is not None and peer_ver == host_ver)


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
        git_exe = shutil.which("git")
        if git_exe is None:
            return version
        out = subprocess.check_output(
            [git_exe, "rev-parse", "--short=12", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
        build = out.decode("utf-8", errors="replace").strip()
        if build:
            if "+" in version:
                return f"{version}.g{build}"
            return f"{version}+g{build}"
    except (OSError, subprocess.CalledProcessError):
        return version
    return version


class Hello(msgspec.Struct, tag="hello", forbid_unknown_fields=True):
    protocol_version: PositiveInt = PROTOCOL_VERSION
    build_id: str = ""
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    tick_rate: PositiveInt = TICK_RATE
    input_delay_ticks: NonNegativeInt = INPUT_DELAY_TICKS
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    host: bool = False


class Welcome(msgspec.Struct, tag="welcome", forbid_unknown_fields=True):
    accepted: bool = False
    reason: str = ""
    session_id: str = ""
    protocol_version: PositiveInt = PROTOCOL_VERSION
    build_id: str = ""
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    slot_index: SignedIndex = -1
    host_slot_index: NonNegativeInt = 0
    tick_rate: PositiveInt = TICK_RATE
    input_delay_ticks: NonNegativeInt = INPUT_DELAY_TICKS
    seed: int = 0
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    started: bool = False


class LobbySlot(SlotState, forbid_unknown_fields=True):
    pass


class LobbyState(msgspec.Struct, tag="lobby_state", forbid_unknown_fields=True):
    session_id: str = ""
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    slots: list[LobbySlot] = msgspec.field(default_factory=list)
    all_ready: bool = False
    started: bool = False
    quest_level: QuestLevel | None = None


class Ready(msgspec.Struct, tag="ready", forbid_unknown_fields=True):
    slot_index: SignedIndex = -1
    ready: bool = False


class MatchStart(msgspec.Struct, tag="match_start", forbid_unknown_fields=True):
    session_id: str = ""
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    seed: int = 0
    start_tick: NonNegativeInt = 0
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    status: GameStatusData | None = None


class InputSample(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: NonNegativeInt = 0
    packed_input: PackedPlayerInput = msgspec.field(default_factory=list)


class InputBatch(msgspec.Struct, tag="input_batch", forbid_unknown_fields=True):
    slot_index: SignedIndex = -1
    samples: list[InputSample] = msgspec.field(default_factory=list)


class TickFrame(msgspec.Struct, tag="tick_frame", forbid_unknown_fields=True):
    tick_index: NonNegativeInt = 0
    frame_inputs: list[PackedPlayerInput] = msgspec.field(default_factory=list)
    commands: list[GameCommand] = msgspec.field(default_factory=list)


class PauseState(msgspec.Struct, tag="pause_state", forbid_unknown_fields=True):
    paused: bool = False
    reason: str = ""


class KeepAlive(msgspec.Struct, tag="keep_alive", forbid_unknown_fields=True):
    """Best-effort keepalive packet to prevent timeouts during stalls/pauses."""

    tick_index: NonNegativeInt = 0


class DebugLogBatch(msgspec.Struct, tag="debug_log_batch", forbid_unknown_fields=True):
    """Client-to-host debug log forwarding payload (best-effort)."""

    slot_index: SignedIndex = -1
    lines: list[str] = msgspec.field(default_factory=list)


class ResyncBegin(msgspec.Struct, tag="resync_begin", forbid_unknown_fields=True):
    stream_id: str = ""
    total_chunks: NonNegativeInt = 0
    compressed_size: NonNegativeInt = 0
    replay_size: NonNegativeInt = 0
    checkpoints_size: NonNegativeInt = 0


class ResyncChunk(msgspec.Struct, tag="resync_chunk", forbid_unknown_fields=True):
    stream_id: str = ""
    chunk_index: NonNegativeInt = 0
    payload: bytes = b""


class ResyncCommit(msgspec.Struct, tag="resync_commit", forbid_unknown_fields=True):
    stream_id: str = ""
    tick_index: SignedIndex = -1


class Disconnect(msgspec.Struct, tag="disconnect", forbid_unknown_fields=True):
    reason: str = ""


type NetMessage = (
    Hello
    | Welcome
    | LobbyState
    | Ready
    | MatchStart
    | TickFrame
    | PauseState
    | KeepAlive
    | DebugLogBatch
    | ResyncBegin
    | ResyncChunk
    | ResyncCommit
    | Disconnect
    | InputBatch
)


class LockstepPacket(PacketHeader, forbid_unknown_fields=True):
    message: NetMessage = msgspec.field(default_factory=PauseState)


_PACKET_DECODER = msgspec.msgpack.Decoder(type=LockstepPacket)


def encode_packet(packet: LockstepPacket) -> bytes:
    return msgspec.msgpack.encode(packet)


def decode_packet(blob: bytes) -> LockstepPacket:
    return _PACKET_DECODER.decode(blob)
