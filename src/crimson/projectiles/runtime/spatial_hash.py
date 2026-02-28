from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState

_SPATIAL_BUCKET_SIZE = 64.0
_NATIVE_FIND_SIZE_SCALE = 0.14285715
_NATIVE_FIND_BASE_MARGIN = 3.0
_NATIVE_FIND_RADIUS_MARGIN_EPS = 0.001


def native_find_margin_for_size(size: float) -> float:
    return float(size) * _NATIVE_FIND_SIZE_SCALE + _NATIVE_FIND_BASE_MARGIN


class CreatureSpatialHash(msgspec.Struct):
    creatures: Sequence[CreatureState]
    is_collidable: Callable[[CreatureState], bool]
    bucket_size: float = _SPATIAL_BUCKET_SIZE
    _bucket_size: float = _SPATIAL_BUCKET_SIZE
    _cells: dict[tuple[int, int], list[int]] = msgspec.field(default_factory=dict)
    _cell_by_index: list[tuple[int, int] | None] = msgspec.field(default_factory=list)
    _max_find_margin: float = 0.0

    def __post_init__(self) -> None:
        if float(self.bucket_size) > 0.0:
            self._bucket_size = float(self.bucket_size)
        self.rebuild()

    def rebuild(self) -> None:
        cells: dict[tuple[int, int], list[int]] = defaultdict(list)
        cell_by_index: list[tuple[int, int] | None] = [None] * len(self.creatures)
        max_find_margin = 0.0

        for idx, creature in enumerate(self.creatures):
            if not self.is_collidable(creature):
                continue
            cell = self._cell_for_pos(creature.pos)
            cells[cell].append(int(idx))
            cell_by_index[int(idx)] = cell
            creature_find_margin = native_find_margin_for_size(float(creature.size))
            if creature_find_margin > max_find_margin:
                max_find_margin = float(creature_find_margin)

        self._cells = cells
        self._cell_by_index = cell_by_index
        self._max_find_margin = float(max_find_margin)

    def sync_index(self, index: int) -> None:
        if not (0 <= int(index) < len(self.creatures)):
            return
        idx = int(index)
        creature = self.creatures[idx]
        previous_cell = self._cell_by_index[idx]
        if not self.is_collidable(creature):
            if previous_cell is not None:
                self._remove_from_cell(idx, previous_cell)
                self._cell_by_index[idx] = None
            return

        next_cell = self._cell_for_pos(creature.pos)
        if previous_cell == next_cell:
            return
        if previous_cell is not None:
            self._remove_from_cell(idx, previous_cell)
        self._cells.setdefault(next_cell, []).append(idx)
        self._cell_by_index[idx] = next_cell

        creature_find_margin = native_find_margin_for_size(float(creature.size))
        if creature_find_margin > self._max_find_margin:
            self._max_find_margin = float(creature_find_margin)

    def candidate_indices(self, *, pos: Vec2, radius: float) -> list[int]:
        if not self._cells:
            return []
        proj_cell_x = int(math.floor(float(pos.x) / self._bucket_size))
        proj_cell_y = int(math.floor(float(pos.y) / self._bucket_size))
        max_axis_delta = float(radius) + float(self._max_find_margin) + _NATIVE_FIND_RADIUS_MARGIN_EPS
        cell_span = int(math.ceil(float(max_axis_delta) / self._bucket_size))

        candidates: list[int] = []
        for cell_y in range(proj_cell_y - cell_span, proj_cell_y + cell_span + 1):
            for cell_x in range(proj_cell_x - cell_span, proj_cell_x + cell_span + 1):
                bucket = self._cells.get((int(cell_x), int(cell_y)))
                if bucket is not None:
                    candidates.extend(bucket)

        if len(candidates) > 1:
            candidates.sort()
        return candidates

    def _cell_for_pos(self, pos: Vec2) -> tuple[int, int]:
        cell_x = int(math.floor(float(pos.x) / self._bucket_size))
        cell_y = int(math.floor(float(pos.y) / self._bucket_size))
        return (cell_x, cell_y)

    def _remove_from_cell(self, index: int, cell: tuple[int, int]) -> None:
        bucket = self._cells.get(cell)
        if bucket is None:
            return
        try:
            bucket.remove(int(index))
        except ValueError:
            return
        if not bucket:
            self._cells.pop(cell, None)


__all__ = ["CreatureSpatialHash", "native_find_margin_for_size"]
