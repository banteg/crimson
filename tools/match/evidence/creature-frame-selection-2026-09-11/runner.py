"""Reuse the existing guarded x86 runner with explicit species-table fixtures."""

import importlib.util
import struct
from pathlib import Path
from unittest.mock import patch

from fixtures import TYPE_INFO

PARENT = Path(__file__).resolve().parent.parent / "creature-render-execution-2026-09-09/verify.py"
spec = importlib.util.spec_from_file_location("creature_render_execution", PARENT)
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)


class Comparison(parent.Comparison):
    def execute(self, side, case):
        factory = parent.unicorn.Uc
        table = self.address("creature_type_table")
        type_info = case.get("type_info", TYPE_INFO)
        assert len(type_info) == 6

        class FixtureMachine:
            def __init__(self, *args, **kwargs):
                self.mu = factory(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.mu, name)

            def emu_start(self, *args, **kwargs):
                # The parent has validated its complete fixture. Replace only
                # these two documented table fields before any x86 executes.
                for index, (base, flags) in enumerate(type_info):
                    for offset, value in ((56, base), (64, flags)):
                        address = table + index * 68 + offset
                        raw = struct.pack("<I", value)
                        self.mu.mem_write(address, raw)
                        assert bytes(self.mu.mem_read(address, 4)) == raw
                return self.mu.emu_start(*args, **kwargs)

        with patch.object(parent.unicorn, "Uc", FixtureMachine):
            return super().execute(side, case)


def atlas_batches(calls):
    batches = []
    active = None
    for name, words in calls:
        if name == "grim_begin_batch":
            assert active is None
            active = []
        elif name == "grim_set_atlas_frame":
            assert active is not None and words[0] == 8
            frame = words[1]
            active.append(frame - 2**32 if frame & 2**31 else frame)
        elif name == "grim_end_batch":
            assert active is not None
            batches.append(active)
            active = None
    assert active is None
    return batches
