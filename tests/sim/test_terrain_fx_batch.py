from __future__ import annotations

from crimson.effects import FxQueueEntry, FxQueueRotatedEntry
from crimson.math_parity import f32
from crimson.sim.terrain_fx import TerrainFxBatch, TerrainFxScratch
from grim.color import RGBA
from grim.geom import Vec2


def _terrain_batch() -> TerrainFxBatch:
    return TerrainFxBatch(
        decals=(
            FxQueueEntry(
                effect_id=5,
                rotation=1.25,
                pos=Vec2(12.0, 34.0),
                width=24.0,
                height=18.0,
                color=RGBA(0.8, 0.7, 0.6, 1.0),
            ),
        ),
        corpses=(
            FxQueueRotatedEntry(
                top_left=Vec2(40.0, 44.0),
                color=RGBA(1.0, 1.0, 1.0, f32(0.8)),
                rotation=0.5,
                scale=f32(1.2),
                creature_type_id=17,
            ),
        ),
    )


def test_terrain_fx_scratch_take_batch_copies_active_entries_and_clears() -> None:
    scratch = TerrainFxScratch()
    scratch.decals.add(
        effect_id=5,
        pos=Vec2(12.0, 34.0),
        width=24.0,
        height=18.0,
        rotation=1.25,
        rgba=RGBA(0.8, 0.7, 0.6, 1.0),
    )
    scratch.corpses.add(
        top_left=Vec2(40.0, 44.0),
        rgba=RGBA(1.0, 1.0, 1.0, 1.0),
        rotation=0.5,
        scale=1.2,
        creature_type_id=17,
    )

    batch = scratch.take_batch()

    assert batch == _terrain_batch()
    assert scratch.decals.count == 0
    assert scratch.corpses.count == 0
    # The next tick reuses the slots; the taken batch keeps its own entries.
    scratch.decals.add(effect_id=6, pos=Vec2(), width=1.0, height=1.0, rotation=0.0, rgba=RGBA())
    assert batch == _terrain_batch()
