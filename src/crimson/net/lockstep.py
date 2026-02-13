from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ..replay.types import PackedPlayerInput
from .protocol import (
    INPUT_DELAY_TICKS,
    INPUT_STALL_TIMEOUT_MS,
    STATE_HASH_PERIOD_TICKS,
    InputBatch,
    InputSample,
    PauseState,
    TickFrame,
)


@dataclass(slots=True)
class HostLockstepState:
    player_count: int
    input_delay_ticks: int = INPUT_DELAY_TICKS
    input_stall_timeout_ms: int = INPUT_STALL_TIMEOUT_MS
    state_hash_period_ticks: int = STATE_HASH_PERIOD_TICKS
    _inputs_by_tick: dict[int, dict[int, PackedPlayerInput]] = field(default_factory=dict)
    _next_emit_tick: int = 0
    _last_progress_ms: int = 0
    _paused: bool = False

    @property
    def next_emit_tick(self) -> int:
        return int(self._next_emit_tick)

    def submit_input_sample(self, *, slot_index: int, tick_index: int, packed_input: PackedPlayerInput) -> None:
        if int(slot_index) < 0 or int(slot_index) >= int(self.player_count):
            return
        if int(tick_index) < int(self._next_emit_tick):
            return
        tick_inputs = self._inputs_by_tick.setdefault(int(tick_index), {})
        tick_inputs[int(slot_index)] = list(packed_input)

    def submit_input_batch(self, batch: InputBatch) -> None:
        slot = int(batch.slot_index)
        for sample in batch.samples:
            self.submit_input_sample(
                slot_index=int(slot),
                tick_index=int(sample.tick_index),
                packed_input=sample.packed_input,
            )

    def _tick_complete(self, tick_index: int) -> bool:
        tick_inputs = self._inputs_by_tick.get(int(tick_index))
        if tick_inputs is None:
            return False
        if len(tick_inputs) < int(self.player_count):
            return False
        return all(int(slot) in tick_inputs for slot in range(int(self.player_count)))

    def pop_ready_frames(
        self,
        *,
        now_ms: int,
        command_hash_by_tick: dict[int, str] | None = None,
        state_hash_by_tick: dict[int, str] | None = None,
    ) -> list[TickFrame]:
        frames: list[TickFrame] = []
        while self._tick_complete(int(self._next_emit_tick)):
            tick = int(self._next_emit_tick)
            tick_inputs = self._inputs_by_tick.pop(tick, {})
            ordered_inputs = [list(tick_inputs[slot]) for slot in range(int(self.player_count))]
            command_hash = ""
            if command_hash_by_tick is not None:
                command_hash = str(command_hash_by_tick.get(int(tick), ""))
            state_hash = ""
            if state_hash_by_tick is not None and (int(tick) % int(self.state_hash_period_ticks)) == 0:
                state_hash = str(state_hash_by_tick.get(int(tick), ""))
            frames.append(
                TickFrame(
                    tick_index=int(tick),
                    frame_inputs=ordered_inputs,
                    command_hash=str(command_hash),
                    state_hash=str(state_hash),
                )
            )
            self._next_emit_tick += 1
            self._last_progress_ms = int(now_ms)

        return frames

    def update_pause_state(self, *, now_ms: int) -> PauseState | None:
        tick_inputs = self._inputs_by_tick.get(int(self._next_emit_tick), {})
        waiting_for = max(0, int(self.player_count) - len(tick_inputs))
        should_pause = waiting_for > 0 and (int(now_ms) - int(self._last_progress_ms)) >= int(self.input_stall_timeout_ms)
        if bool(should_pause) == bool(self._paused):
            return None
        self._paused = bool(should_pause)
        if should_pause:
            return PauseState(paused=True, reason="waiting_input")
        return PauseState(paused=False, reason="")


@dataclass(slots=True)
class ClientLockstepState:
    local_slot_index: int
    input_delay_ticks: int = INPUT_DELAY_TICKS
    input_stall_timeout_ms: int = INPUT_STALL_TIMEOUT_MS
    _capture_tick: int = 0
    _sent_inputs: dict[int, PackedPlayerInput] = field(default_factory=dict)
    _canonical_by_tick: dict[int, TickFrame] = field(default_factory=dict)
    _next_consume_tick: int = 0
    _last_progress_ms: int = 0
    _paused: bool = False
    _pending_desync: deque[tuple[int, str, str]] = field(default_factory=deque)

    @property
    def next_consume_tick(self) -> int:
        return int(self._next_consume_tick)

    def queue_local_input(self, packed_input: PackedPlayerInput) -> InputBatch:
        target_tick = int(self._capture_tick + int(self.input_delay_ticks))
        self._sent_inputs[int(target_tick)] = list(packed_input)

        samples: list[InputSample] = []
        for tick in range(int(target_tick), int(target_tick) - 3, -1):
            value = self._sent_inputs.get(int(tick))
            if value is None:
                continue
            samples.append(InputSample(tick_index=int(tick), packed_input=list(value)))

        self._capture_tick += 1
        return InputBatch(slot_index=int(self.local_slot_index), samples=samples)

    def ingest_tick_frame(self, frame: TickFrame, *, now_ms: int, local_command_hash: str = "") -> None:
        tick = int(frame.tick_index)
        self._canonical_by_tick[int(tick)] = frame
        self._last_progress_ms = int(now_ms)
        remote_hash = str(frame.command_hash or "")
        if remote_hash and str(local_command_hash or "") and str(local_command_hash) != str(remote_hash):
            self._pending_desync.append((int(tick), str(remote_hash), str(local_command_hash)))

    def pop_canonical_frame(self) -> TickFrame | None:
        tick = int(self._next_consume_tick)
        frame = self._canonical_by_tick.pop(int(tick), None)
        if frame is None:
            return None
        self._next_consume_tick += 1
        return frame

    def pop_desync_notice(self) -> tuple[int, str, str] | None:
        if not self._pending_desync:
            return None
        return self._pending_desync.popleft()

    def update_pause_state(self, *, now_ms: int) -> PauseState | None:
        frame_ready = int(self._next_consume_tick) in self._canonical_by_tick
        should_pause = (not frame_ready) and (
            int(now_ms) - int(self._last_progress_ms)
        ) >= int(self.input_stall_timeout_ms)
        if bool(should_pause) == bool(self._paused):
            return None
        self._paused = bool(should_pause)
        if should_pause:
            return PauseState(paused=True, reason="waiting_tick_frame")
        return PauseState(paused=False, reason="")
