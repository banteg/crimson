from __future__ import annotations

from dataclasses import dataclass, field

from ..replay.types import PackedPlayerInput
from .lockstep import ClientLockstepState, HostLockstepState
from .protocol import InputBatch, PauseState, TickFrame


@dataclass(slots=True)
class ResyncFailureTracker:
    max_failures_per_match: int = 2
    failures: int = 0

    def note_failure(self) -> bool:
        self.failures += 1
        return int(self.failures) >= int(self.max_failures_per_match)

    def reset(self) -> None:
        self.failures = 0


@dataclass(slots=True)
class HostLanAdapter:
    player_count: int
    input_delay_ticks: int = 2
    input_stall_timeout_ms: int = 250
    state_hash_period_ticks: int = 120
    local_slot_index: int = 0
    lockstep: HostLockstepState = field(init=False)
    resync_failures: ResyncFailureTracker = field(default_factory=ResyncFailureTracker)

    def __post_init__(self) -> None:
        self.lockstep = HostLockstepState(
            player_count=int(self.player_count),
            input_delay_ticks=int(self.input_delay_ticks),
            input_stall_timeout_ms=int(self.input_stall_timeout_ms),
            state_hash_period_ticks=int(self.state_hash_period_ticks),
        )

    def submit_local_input(self, *, tick_index: int, packed_input: PackedPlayerInput) -> None:
        self.lockstep.submit_input_sample(
            slot_index=int(self.local_slot_index),
            tick_index=int(tick_index),
            packed_input=list(packed_input),
        )

    def submit_remote_batch(self, batch: InputBatch) -> None:
        self.lockstep.submit_input_batch(batch)

    def emit_ready_frames(
        self,
        *,
        now_ms: int,
        command_hash_by_tick: dict[int, str] | None = None,
        state_hash_by_tick: dict[int, str] | None = None,
    ) -> list[TickFrame]:
        return self.lockstep.pop_ready_frames(
            now_ms=int(now_ms),
            command_hash_by_tick=command_hash_by_tick,
            state_hash_by_tick=state_hash_by_tick,
        )

    def update_pause_state(self, *, now_ms: int) -> PauseState | None:
        return self.lockstep.update_pause_state(now_ms=int(now_ms))


@dataclass(slots=True)
class ClientLanAdapter:
    local_slot_index: int
    input_delay_ticks: int = 2
    input_stall_timeout_ms: int = 250
    lockstep: ClientLockstepState = field(init=False)
    resync_failures: ResyncFailureTracker = field(default_factory=ResyncFailureTracker)

    def __post_init__(self) -> None:
        self.lockstep = ClientLockstepState(
            local_slot_index=int(self.local_slot_index),
            input_delay_ticks=int(self.input_delay_ticks),
            input_stall_timeout_ms=int(self.input_stall_timeout_ms),
        )

    def queue_local_input(self, packed_input: PackedPlayerInput) -> InputBatch:
        return self.lockstep.queue_local_input(list(packed_input))

    def ingest_tick_frame(self, frame: TickFrame, *, now_ms: int, local_command_hash: str = "") -> None:
        self.lockstep.ingest_tick_frame(
            frame,
            now_ms=int(now_ms),
            local_command_hash=str(local_command_hash),
        )

    def pop_tick_frame(self) -> TickFrame | None:
        return self.lockstep.pop_canonical_frame()

    def pop_desync_notice(self) -> tuple[int, str, str] | None:
        return self.lockstep.pop_desync_notice()

    def update_pause_state(self, *, now_ms: int) -> PauseState | None:
        return self.lockstep.update_pause_state(now_ms=int(now_ms))
