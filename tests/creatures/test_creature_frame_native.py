"""Frame indices observed from the original x86 renderer at gameplay precision."""

import json
from pathlib import Path

from crimson.creatures.anim import creature_anim_select_flash_frame, creature_anim_select_frame
from crimson.creatures.spawn import CreatureFlags

FIXTURES = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/creature-frame-selection.json"


def test_creature_frames_match_native_pc24_witnesses() -> None:
    data = json.loads(FIXTURES.read_text())
    assert data["fpcw"] == 0x7F
    assert len(data["witnesses"]) == 2640
    for witness in data["witnesses"]:
        actual, _, _ = creature_anim_select_frame(
            witness["phase"],
            lifecycle_stage=witness["lifecycle_stage"],
            base_frame=witness["base_frame"],
            mirror_long=witness["mirror_long"],
            flags=CreatureFlags(witness["flags"]),
        )
        assert actual == witness["frame"], witness
        flash, _, _ = creature_anim_select_flash_frame(
            witness["phase"],
            lifecycle_stage=witness["lifecycle_stage"],
            base_frame=witness["base_frame"],
            mirror_long=witness["mirror_long"],
            flags=CreatureFlags(witness["flags"]),
        )
        assert flash == witness["flash_frame"], witness
