from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ..replay.types import PackedPlayerInput
from .relay_protocol import RbInputBatch, RbInputSample

_NEUTRAL_INPUT: PackedPlayerInput = [0.0, 0.0, 0.0, 0.0, 0]
_MAX_SENT_HISTORY_TICKS = 256
_MAX_RESEND_SAMPLES = 64


@dataclass(frozen=True, slots=True)
class RollbackFrame:
    tick_index: int
    frame_inputs: list[PackedPlayerInput]
    predicted_slots: tuple[int, ...] = ()


@dataclass(slots=True)
class RollbackController:
    """Input timeline + prediction + rollback trigger bookkeeping.

    This controller does not mutate game state directly. It emits canonical tick
    inputs and reports rollback windows when late remote inputs disagree with
    previously-emitted predicted inputs.
    """

    player_count: int
    local_slot_index: int
    input_delay_ticks: int = 1
    max_rollback_ticks: int = 8
    max_sent_history_ticks: int = _MAX_SENT_HISTORY_TICKS
    max_resend_samples: int = _MAX_RESEND_SAMPLES

    _capture_tick: int = 0
    _next_emit_tick: int = 0
    _known_by_slot: dict[int, dict[int, PackedPlayerInput]] = field(default_factory=dict)
    _emitted_frames: dict[int, list[PackedPlayerInput]] = field(default_factory=dict)
    _pending_frames: deque[RollbackFrame] = field(default_factory=deque)
    _pending_rollback_from: int | None = None
    _pending_resync_from: int | None = None

    rollback_count: int = 0
    prediction_mismatches: int = 0
    max_rollback_distance: int = 0

    def __post_init__(self) -> None:
        players = max(1, int(self.player_count))
        self.player_count = int(players)
        slot = max(0, min(int(self.local_slot_index), int(players) - 1))
        self.local_slot_index = int(slot)
        self.input_delay_ticks = max(0, int(self.input_delay_ticks))
        self.max_rollback_ticks = max(1, int(self.max_rollback_ticks))
        for slot_index in range(int(self.player_count)):
            self._known_by_slot[int(slot_index)] = {}

    @property
    def capture_tick(self) -> int:
        return int(self._capture_tick)

    @property
    def next_emit_tick(self) -> int:
        return int(self._next_emit_tick)

    def queue_local_input(self, packed_input: PackedPlayerInput) -> RbInputBatch:
        target_tick = int(self._capture_tick) + int(self.input_delay_ticks)
        self._known_by_slot[int(self.local_slot_index)][int(target_tick)] = list(packed_input)

        history = max(1, int(self.max_sent_history_ticks))
        oldest = max(int(self._next_emit_tick), int(target_tick) - int(history) + 1)
        max_samples = max(1, int(self.max_resend_samples))

        samples: list[RbInputSample] = []
        slot_map = self._known_by_slot[int(self.local_slot_index)]
        count = 0
        for tick in range(int(target_tick), int(oldest) - 1, -1):
            value = slot_map.get(int(tick))
            if value is None:
                continue
            samples.append(RbInputSample(tick_index=int(tick), packed_input=list(value)))
            count += 1
            if count >= int(max_samples):
                break

        for tick in list(slot_map.keys()):
            if int(tick) < int(oldest) or int(tick) > int(target_tick):
                slot_map.pop(int(tick), None)

        self._capture_tick += 1
        self._emit_ready_frames()
        return RbInputBatch(slot_index=int(self.local_slot_index), samples=samples)

    def ingest_remote_samples(self, *, slot_index: int, samples: list[RbInputSample]) -> None:
        slot = int(slot_index)
        if slot < 0 or slot >= int(self.player_count):
            return
        if slot == int(self.local_slot_index):
            return
        known = self._known_by_slot[int(slot)]
        for sample in samples:
            tick = int(sample.tick_index)
            if tick < 0:
                continue
            incoming = list(sample.packed_input)
            prev = known.get(int(tick))
            known[int(tick)] = incoming
            if prev is not None and prev == incoming:
                continue
            self._note_late_mismatch(slot_index=int(slot), tick_index=int(tick), incoming=incoming)
        self._emit_ready_frames()

    def pop_frame(self) -> RollbackFrame | None:
        if not self._pending_frames:
            return None
        return self._pending_frames.popleft()

    def drain_rollback_from(self) -> int | None:
        value = self._pending_rollback_from
        self._pending_rollback_from = None
        return None if value is None else int(value)

    def drain_resync_from(self) -> int | None:
        value = self._pending_resync_from
        self._pending_resync_from = None
        return None if value is None else int(value)

    def rebuild_emitted_from(self, from_tick: int) -> list[RollbackFrame]:
        start = max(0, int(from_tick))
        head = int(self._next_emit_tick)
        if start >= int(head):
            return []

        rebuilt: list[RollbackFrame] = []
        for tick in range(int(start), int(head)):
            predicted_slots: list[int] = []
            frame_inputs: list[PackedPlayerInput] = []
            for slot in range(int(self.player_count)):
                value = self._known_for_tick(int(slot), int(tick))
                if value is None:
                    predicted_slots.append(int(slot))
                    value = self._predict_for_tick(int(slot), int(tick))
                frame_inputs.append(list(value))
            self._emitted_frames[int(tick)] = [list(item) for item in frame_inputs]
            rebuilt.append(
                RollbackFrame(
                    tick_index=int(tick),
                    frame_inputs=[list(item) for item in frame_inputs],
                    predicted_slots=tuple(predicted_slots),
                ),
            )
        return rebuilt

    def reset_to_tick(self, tick_index: int) -> None:
        target = max(0, int(tick_index))
        self._capture_tick = max(int(self._capture_tick), int(target))
        self._next_emit_tick = max(int(self._next_emit_tick), int(target))
        self._pending_frames.clear()
        self._pending_rollback_from = None
        self._pending_resync_from = None
        for slot_map in self._known_by_slot.values():
            for tick in list(slot_map.keys()):
                if int(tick) >= int(target):
                    continue
                slot_map.pop(int(tick), None)
        for tick in list(self._emitted_frames.keys()):
            if int(tick) >= int(target):
                continue
            self._emitted_frames.pop(int(tick), None)

    def _emit_ready_frames(self) -> None:
        local_known = self._known_by_slot[int(self.local_slot_index)]
        while int(self._next_emit_tick) in local_known:
            tick = int(self._next_emit_tick)
            predicted_slots: list[int] = []
            frame_inputs: list[PackedPlayerInput] = []
            for slot in range(int(self.player_count)):
                value = self._known_for_tick(int(slot), int(tick))
                if value is None:
                    predicted_slots.append(int(slot))
                    value = self._predict_for_tick(int(slot), int(tick))
                frame_inputs.append(list(value))
            self._pending_frames.append(
                RollbackFrame(
                    tick_index=int(tick),
                    frame_inputs=[list(item) for item in frame_inputs],
                    predicted_slots=tuple(predicted_slots),
                ),
            )
            self._emitted_frames[int(tick)] = [list(item) for item in frame_inputs]
            self._next_emit_tick += 1
            self._prune_emitted()

    def _known_for_tick(self, slot: int, tick: int) -> PackedPlayerInput | None:
        return self._known_by_slot[int(slot)].get(int(tick))

    def _predict_for_tick(self, slot: int, tick: int) -> PackedPlayerInput:
        known = self._known_by_slot[int(slot)]
        for back in range(int(tick) - 1, -1, -1):
            value = known.get(int(back))
            if value is not None:
                return list(value)
        return list(_NEUTRAL_INPUT)

    def _note_late_mismatch(self, *, slot_index: int, tick_index: int, incoming: PackedPlayerInput) -> None:
        emitted = self._emitted_frames.get(int(tick_index))
        if emitted is None:
            return
        if int(slot_index) >= len(emitted):
            return
        predicted = emitted[int(slot_index)]
        if list(predicted) == list(incoming):
            return

        self.prediction_mismatches = int(self.prediction_mismatches) + 1
        distance = max(0, int(self._next_emit_tick) - int(tick_index))
        self.max_rollback_distance = max(int(self.max_rollback_distance), int(distance))

        if int(distance) > int(self.max_rollback_ticks):
            pending = self._pending_resync_from
            if pending is None:
                self._pending_resync_from = int(tick_index)
            else:
                self._pending_resync_from = min(int(pending), int(tick_index))
            return

        self.rollback_count = int(self.rollback_count) + 1
        pending = self._pending_rollback_from
        if pending is None:
            self._pending_rollback_from = int(tick_index)
        else:
            self._pending_rollback_from = min(int(pending), int(tick_index))

    def _prune_emitted(self) -> None:
        keep_from = int(self._next_emit_tick) - max(1, int(self.max_rollback_ticks)) - 2
        for tick in list(self._emitted_frames.keys()):
            if int(tick) >= int(keep_from):
                continue
            self._emitted_frames.pop(int(tick), None)


__all__ = ["RollbackController", "RollbackFrame"]
