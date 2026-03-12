from __future__ import annotations

from crimson.sim.batch_apply import PresentationTickOutput, apply_presentation_outputs
from crimson.sim.presentation_step import PresentationStepCommands
from crimson.sim.terrain_fx import TerrainCorpseFx, TerrainDecalFx, TerrainFxBatch, TerrainFxScratch
from grim.color import RGBA
from grim.geom import Vec2


def _terrain_batch() -> TerrainFxBatch:
    return TerrainFxBatch(
        decals=(
            TerrainDecalFx(
                effect_id=5,
                rotation=1.25,
                pos=Vec2(12.0, 34.0),
                width=24.0,
                height=18.0,
                color=RGBA(0.8, 0.7, 0.6, 1.0),
            ),
        ),
        corpses=(
            TerrainCorpseFx(
                top_left=Vec2(40.0, 44.0),
                color=RGBA(1.0, 1.0, 1.0, 0.8),
                rotation=0.5,
                scale=1.2,
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


def test_apply_presentation_outputs_applies_terrain_fx_in_output_order() -> None:
    calls: list[tuple[str, int | None]] = []
    outputs = (
        PresentationTickOutput(
            tick_index=1,
            dt_sim=1.0 / 60.0,
            presentation=PresentationStepCommands(),
            terrain_fx=_terrain_batch(),
        ),
        PresentationTickOutput(
            tick_index=2,
            dt_sim=1.0 / 60.0,
            presentation=None,
            terrain_fx=_terrain_batch(),
        ),
    )

    apply_presentation_outputs(
        outputs=outputs,
        sync_audio_bridge_state=lambda: calls.append(("sync", None)),
        apply_audio_plan=lambda _plan, _apply_audio: calls.append(("audio", 1)),
        apply_terrain_fx=lambda _batch: calls.append(("terrain", 1)),
        update_camera=lambda _dt: calls.append(("camera", 1)),
        on_output_applied=lambda output: calls.append(("done", int(output.tick_index))),
        apply_audio=True,
    )

    assert calls == [
        ("sync", None),
        ("audio", 1),
        ("camera", 1),
        ("terrain", 1),
        ("done", 1),
        ("terrain", 1),
        ("done", 2),
    ]
