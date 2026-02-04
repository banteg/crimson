from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..gameplay import PlayerInput
from ..perks import PerkId
from .crdemo import ActionType, Demo, DemoAction, DemoError, DemoFrame, DemoHeader, PlayerInit, dump


@dataclass(slots=True)
class DemoRecorder:
    header: DemoHeader
    frames: list[DemoFrame] = field(default_factory=list)
    actions: list[DemoAction] = field(default_factory=list)

    def tick(self) -> int:
        return len(self.frames)

    def record_frame(self, dt: float, inputs: list[PlayerInput]) -> None:
        self.frames.append(DemoFrame(dt=float(dt), inputs=tuple(inputs)))

    def record_perk_pick(self, *, player_index: int, perk_id: PerkId, dt: float) -> None:
        self.actions.append(
            DemoAction(
                tick=int(self.tick()),
                action_type=int(ActionType.PERK_PICK),
                player_index=int(player_index),
                payload_u16=int(perk_id) & 0xFFFF,
                payload_f32=float(dt),
            )
        )

    def finalize(self) -> Demo:
        player_count = int(self.header.player_count)
        if len(self.header.player_inits) != player_count:
            raise DemoError("player init count mismatch")
        for frame in self.frames:
            if len(frame.inputs) != player_count:
                raise DemoError("frame input count mismatch")
        return Demo(header=self.header, frames=tuple(self.frames), actions=tuple(self.actions))

    def save(self, path: Path) -> None:
        demo = self.finalize()
        path.parent.mkdir(parents=True, exist_ok=True)
        dump(demo, path)

