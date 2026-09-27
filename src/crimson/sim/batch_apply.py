from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from .presentation_step import DeterministicPresentationPlan

if TYPE_CHECKING:
    from ..world.runtime import WorldRuntime


def apply_presentation_plans(
    *,
    plans: Sequence[DeterministicPresentationPlan],
    runtime: WorldRuntime,
) -> None:
    if not plans:
        return

    runtime.sync_audio_bridge_state()
    for plan in plans:
        # Capture the viewport before this tick's post-step camera update.
        # Camera updates carry tick-local focus/shake, so batched application
        # never reads positions from a later simulation world.
        view = runtime.view_transform()
        runtime.audio_bridge.apply_plan(
            plan=plan,
            camera=view.camera,
            screen_width=view.screen_size.x,
        )
        if plan.camera is not None:
            runtime.update_camera(plan.camera)
        if not plan.terrain_fx.is_empty():
            runtime.render_resources.consume_terrain_fx_batch(plan.terrain_fx)
        runtime.audio_bridge.apply_post_plan(
            plan=plan,
            camera=view.camera,
            screen_width=view.screen_size.x,
        )
