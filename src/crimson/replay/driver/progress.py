from __future__ import annotations

from typing import Literal

import msgspec

ReplayRenderPhase = Literal["video", "audio"]


class ReplayRenderProgress(msgspec.Struct):
    def update(
        self,
        *,
        phase: ReplayRenderPhase,
        frame_count: int,
        tick_index: int,
        total_ticks: int,
    ) -> None:
        _ = phase, frame_count, tick_index, total_ticks

    def close(self) -> None:
        return None
