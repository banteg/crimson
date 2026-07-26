from __future__ import annotations

import msgspec

from ..replay.types import PackedPlayerInput
from .lockstep_protocol import (
    INPUT_DELAY_TICKS,
    INPUT_STALL_TIMEOUT_MS,
    InputBatch,
    InputSample,
    PauseState,
    TickFrame,
)

CLIENT_MAX_CAPTURE_LEAD_TICKS = 1
CLIENT_MAX_RESEND_SAMPLES = 64
CLIENT_MAX_SENT_HISTORY_TICKS = 256


class HostLockstepState(msgspec.Struct):
    player_count: int
    input_delay_ticks: int = INPUT_DELAY_TICKS
    input_stall_timeout_ms: int = INPUT_STALL_TIMEOUT_MS
    _inputs_by_tick: dict[int, dict[int, PackedPlayerInput]] = msgspec.field(default_factory=dict)
    _next_emit_tick: int = 0
    _last_progress_ms: int = 0
    _paused: bool = False

    @property
    def next_emit_tick(self) -> int:
        return int(self._next_emit_tick)

    @property
    def buffered_tick_count(self) -> int:
        return len(self._inputs_by_tick)

    @property
    def paused(self) -> bool:
        return bool(self._paused)

    @property
    def last_progress_ms(self) -> int:
        return int(self._last_progress_ms)

    def waiting_for_inputs(self, *, tick_index: int | None = None) -> int:
        if tick_index is None:
            tick_index = int(self._next_emit_tick)
        tick_inputs = self._inputs_by_tick.get(int(tick_index), {})
        return max(0, int(self.player_count) - len(tick_inputs))

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
    ) -> list[HostReadyTick]:
        frames: list[HostReadyTick] = []
        while self._tick_complete(int(self._next_emit_tick)):
            tick = int(self._next_emit_tick)
            tick_inputs = self._inputs_by_tick.pop(tick, {})
            ordered_inputs = [list(tick_inputs[slot]) for slot in range(int(self.player_count))]
            frames.append(
                HostReadyTick(
                    tick_index=int(tick),
                    frame_inputs=ordered_inputs,
                ),
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


class HostReadyTick(msgspec.Struct):
    tick_index: int = 0
    frame_inputs: list[PackedPlayerInput] = msgspec.field(default_factory=list)


class ClientLockstepState(msgspec.Struct):
    local_slot_index: int
    input_delay_ticks: int = INPUT_DELAY_TICKS
    input_stall_timeout_ms: int = INPUT_STALL_TIMEOUT_MS
    max_resend_samples: int = CLIENT_MAX_RESEND_SAMPLES
    max_sent_history_ticks: int = CLIENT_MAX_SENT_HISTORY_TICKS
    _capture_tick: int = 0
    _sent_inputs: dict[int, PackedPlayerInput] = msgspec.field(default_factory=dict)
    _canonical_by_tick: dict[int, TickFrame] = msgspec.field(default_factory=dict)
    _next_consume_tick: int = 0
    _last_progress_ms: int = 0
    _paused: bool = False


    @property
    def next_consume_tick(self) -> int:
        return int(self._next_consume_tick)

    @property
    def capture_tick(self) -> int:
        return int(self._capture_tick)

    @property
    def buffered_frame_count(self) -> int:
        return len(self._canonical_by_tick)

    @property
    def paused(self) -> bool:
        return bool(self._paused)

    @property
    def last_progress_ms(self) -> int:
        return int(self._last_progress_ms)

    def queue_local_input(self, packed_input: PackedPlayerInput) -> InputBatch:
        # Keep the joiner's "capture clock" close to lockstep progress to avoid
        # scheduling inputs far in the future (which manifests as extra input lag).
        max_capture_tick = int(self._next_consume_tick) + int(CLIENT_MAX_CAPTURE_LEAD_TICKS)
        if int(self._capture_tick) > int(max_capture_tick):
            self._capture_tick = int(max_capture_tick)

        target_tick = int(self._capture_tick + int(self.input_delay_ticks))
        self._sent_inputs[int(target_tick)] = list(packed_input)

        samples: list[InputSample] = []
        oldest_tick = max(0, int(self._next_consume_tick))
        history_ticks = int(self.max_sent_history_ticks)
        if history_ticks > 0:
            oldest_tick = max(int(oldest_tick), int(target_tick) - int(history_ticks) + 1)
        max_samples = max(1, int(self.max_resend_samples))
        sample_count = 0
        for tick in range(int(target_tick), int(oldest_tick) - 1, -1):
            value = self._sent_inputs.get(int(tick))
            if value is None:
                continue
            samples.append(InputSample(tick_index=int(tick), packed_input=list(value)))
            sample_count += 1
            if int(sample_count) >= int(max_samples):
                break

        # Keep memory bounded while preserving any still-unacknowledged ticks.
        min_keep_tick = max(0, int(self._next_consume_tick))
        if history_ticks > 0:
            min_keep_tick = max(int(min_keep_tick), int(target_tick) - int(history_ticks) + 1)
        max_keep_tick = int(target_tick)
        for tick in list(self._sent_inputs):
            if int(tick) < int(min_keep_tick) or int(tick) > int(max_keep_tick):
                self._sent_inputs.pop(int(tick), None)

        self._capture_tick += 1
        return InputBatch(slot_index=int(self.local_slot_index), samples=samples)

    def ingest_tick_frame(self, frame: TickFrame, *, now_ms: int) -> None:
        tick = int(frame.tick_index)
        self._canonical_by_tick[int(tick)] = TickFrame(
            tick_index=int(frame.tick_index),
            frame_inputs=[list(item) for item in frame.frame_inputs],
            commands=list(frame.commands),
        )
        self._last_progress_ms = int(now_ms)

    def pop_canonical_frame(self) -> TickFrame | None:
        tick = int(self._next_consume_tick)
        frame = self._canonical_by_tick.pop(int(tick), None)
        if frame is None:
            return None
        self._next_consume_tick += 1
        return frame

    def has_canonical_frame(self) -> bool:
        return int(self._next_consume_tick) in self._canonical_by_tick

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
