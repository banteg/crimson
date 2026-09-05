from __future__ import annotations

from crimson.sim.batch_apply import PresentationTickOutput, apply_presentation_outputs
from crimson.sim.presentation_step import DeterministicPresentationPlan
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


class _PresentationAudioBridge:
    def __init__(self, calls: list[tuple[str, int | None]]) -> None:
        self._calls = calls

    def apply_plan(self, *, plan: DeterministicPresentationPlan, apply_audio: bool = True) -> None:
        _ = plan, apply_audio
        self._calls.append(("audio", 1))

    def apply_post_plan(self, **_kwargs) -> None:
        self._calls.append(("done", 1))


class _PresentationRenderResources:
    def __init__(self, calls: list[tuple[str, int | None]]) -> None:
        self._calls = calls

    def consume_terrain_fx_batch(self, batch: TerrainFxBatch) -> None:
        _ = batch
        self._calls.append(("terrain", 1))


class _PresentationRuntime:
    def __init__(self, calls: list[tuple[str, int | None]]) -> None:
        self._calls = calls
        self.audio_bridge = _PresentationAudioBridge(calls)
        self.render_resources = _PresentationRenderResources(calls)

    def sync_audio_bridge_state(self) -> None:
        self._calls.append(("sync", None))

    def update_camera(self, dt: float) -> None:
        _ = dt
        self._calls.append(("camera", 1))


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
            presentation=DeterministicPresentationPlan(terrain_fx=_terrain_batch()),
        ),
        PresentationTickOutput(
            tick_index=2,
            dt_sim=1.0 / 60.0,
            presentation=DeterministicPresentationPlan(terrain_fx=_terrain_batch()),
        ),
    )

    apply_presentation_outputs(
        outputs=outputs,
        runtime=_PresentationRuntime(calls),
        apply_audio=True,
    )

    assert calls == [
        ("sync", None),
        ("audio", 1),
        ("camera", 1),
        ("terrain", 1),
        ("done", 1),
        ("audio", 1),
        ("camera", 1),
        ("terrain", 1),
        ("done", 1),
    ]
