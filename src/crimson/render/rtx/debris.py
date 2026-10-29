"""Loose freeze debris, bounded as the clients bound it (crimson-core/game/include/rtx_debris.h).

A dense Freeze burst leaves a thousand or more ice cubes and shards in the effect pool, each lit by the full RTX
pass. At most TARGET of them draw, spread across the screen's 8x6 tiles and within half its area; one leaving the
selection fades out over FADE_SECONDS of the run's clock while one joining fades in, and no more than MAXIMUM draw at
once. Only which pieces draw, and how opaque, changes: the effect pool, its draw order and the baked decals are the
native ones. Living creatures' ice never comes here.
"""

from __future__ import annotations

import math

import msgspec

from grim.geom import Vec2
from grim.math import f32

from ...effects import EffectPool
from ...effects_atlas import EffectId

ICE_EFFECTS = frozenset({EffectId.FREEZE_SHATTER, EffectId.FREEZE_SHARD_0, EffectId.FREEZE_SHARD_1, EffectId.FREEZE_SHARD_2})
TARGET = 256
MAXIMUM = 320
FADE_SECONDS = .08
# A rewind, or a gap in the run's clock longer than this, starts the selection over.
GAP_MS = 250.
# The screen's tiles the selection takes its pieces from in turn.
TILES_X, TILES_Y = 8, 6


class Candidate(msgspec.Struct, frozen=True):
    """A piece of debris on screen: its pool slot, the slot's spawn (EffectPool.generation_for_slot), its centre in
    logical screen pixels and the area of its rotated bounds on the screen."""

    slot: int
    generation: int
    x: float
    y: float
    area: float


class _Piece(msgspec.Struct):
    generation: int
    alpha: float = 0.
    seen: bool = False


def _key(slot: int) -> int:
    """The slot's stable place in the selection, the clients' integer hash."""
    key = slot ^ slot >> 16
    key = key * 0x7feb352d & 0xffffffff
    key ^= key >> 15
    key = key * 0x846ca68b & 0xffffffff
    return key ^ key >> 16


def candidates(pool: EffectPool, *, camera: Vec2, screen: Vec2) -> list[Candidate]:
    """The pool's debris that shows on a `screen` of logical pixels."""
    out = []
    for slot, entry in enumerate((*pool.entries, *pool.overflow_entries)):
        if not entry.flags or entry.age < 0. or entry.effect_id not in ICE_EFFECTS or entry.color.a < 1. / 255.:
            continue
        x, y = entry.pos.x + camera.x, entry.pos.y + camera.y
        co, si = abs(math.cos(entry.rotation)), abs(math.sin(entry.rotation))
        w = (co * entry.half_width + si * entry.half_height) * abs(entry.scale)
        h = (si * entry.half_width + co * entry.half_height) * abs(entry.scale)
        area = max(0., min(screen.x, x + w) - max(0., x - w)) * max(0., min(screen.y, y + h) - max(0., y - h))
        if area > 0.:
            out.append(Candidate(slot, pool.generation_for_slot(slot), x, y, area))
    return out


class DebrisBudget(msgspec.Struct):
    """Each shown piece's opacity in the selection, by pool slot."""

    pieces: dict[int, _Piece] = msgspec.field(default_factory=dict)
    elapsed_ms: float = -1.

    def reset(self) -> None:
        self.pieces.clear()
        self.elapsed_ms = -1.

    def alpha(self, slot: int) -> float:
        piece = self.pieces.get(slot)
        return piece.alpha if piece is not None else 0.

    def select(self, shown: list[Candidate], *, screen: Vec2, elapsed_ms: float) -> None:
        """Choose this frame's pieces from those `shown`, at `elapsed_ms` of the run's clock: a redraw at the same
        time moves no fade."""
        gap = elapsed_ms - self.elapsed_ms
        if self.elapsed_ms < 0. or gap < 0. or gap > GAP_MS:
            self.reset()
            gap = 0.
        self.elapsed_ms = elapsed_ms
        if not (screen.x > 0. and screen.y > 0.):
            self.pieces.clear()
            return
        # A slot that shows nothing forgets its piece, as does one a new spawn took.
        pieces = {}
        for c in shown:
            piece = self.pieces.get(c.slot)
            pieces[c.slot] = piece if piece is not None and piece.generation == c.generation else _Piece(c.generation)
        self.pieces = pieces
        # Round-robin across the occupied tiles, each in its pieces' stable order.
        tiles = []
        occupied = [0] * (TILES_X * TILES_Y)
        for c in sorted(shown, key=lambda c: _key(c.slot)):
            tile = min(max(int(c.y * TILES_Y / screen.y), 0), TILES_Y - 1) * TILES_X + \
                min(max(int(c.x * TILES_X / screen.x), 0), TILES_X - 1)
            tiles.append((occupied[tile], _key(c.slot), c))
            occupied[tile] += 1
        ranked = [c for _, _, c in sorted(tiles, key=lambda t: t[:2])]
        whole = screen.x * screen.y
        wanted = set()
        area = 0.
        for c in ranked:
            if len(wanted) == TARGET or area + c.area > whole * .5:
                continue
            wanted.add(c.slot)
            area += c.area
        # In the clients' single precision, so a fade ends where theirs does: on zero.
        step = min(max(f32(f32(gap * f32(.001)) / f32(FADE_SECONDS)), 0.), 1.)
        for slot, piece in pieces.items():
            if slot not in wanted:
                piece.alpha = max(0., f32(piece.alpha - step))
        # The pieces still drawn hold their whole quads and areas while they fade; a joining piece waits for room.
        drawn = [c for c in ranked if pieces[c.slot].alpha > 0.]
        count, area = len(drawn), sum(c.area for c in drawn)
        for c in ranked:
            piece = pieces[c.slot]
            if c.slot in wanted:
                if piece.alpha > 0.:
                    piece.alpha = min(1., f32(piece.alpha + step))
                elif count < MAXIMUM and area + c.area <= whole * .75:
                    # A new piece keeps its own onset; one the budget held back fades in.
                    piece.alpha = step if piece.seen else 1.
                    if piece.alpha > 0.:
                        count += 1
                        area += c.area
            piece.seen = True
