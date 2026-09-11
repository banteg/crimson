"""Read entry-relative stack pointers without changing the parent machine runner."""

import importlib.util
from pathlib import Path
from unittest.mock import patch

PARENT = Path(__file__).resolve().parent.parent / "overlay-tint-trail-2026-09-11"
spec = importlib.util.spec_from_file_location("overlay_size_parent", PARENT / "runner.py")
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)
match, Program = parent.match, parent.Program
sha = parent.sha


def run(program, native, frame):
    original = parent.unicorn.Uc
    start = program.native_start if native else program.candidate_start
    end = program.native_end if native else start + len(program.body.data)
    offsets = {}
    final = {}

    class ObservedMachine:
        def __init__(self, *args, **kwargs):
            self.machine = original(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.machine, name)

        def emu_start(self, *args, **kwargs):
            entry = self.machine.reg_read(parent.x86.UC_X86_REG_ESP)

            def read_stack(machine, address, size, data):
                if start <= address < end:
                    offset = machine.reg_read(parent.x86.UC_X86_REG_ESP) - entry
                    relative = address - start
                    assert relative not in offsets or offsets[relative] == offset
                    offsets[relative] = offset

            self.machine.hook_add(parent.unicorn.UC_HOOK_CODE, read_stack)
            result = self.machine.emu_start(*args, **kwargs)
            final["control_word"] = self.machine.reg_read(parent.x86.UC_X86_REG_FPCW)
            final["tag_word"] = self.machine.reg_read(parent.x86.UC_X86_REG_FPTAG)
            assert final == {"control_word": 0x37F, "tag_word": 0xFFFF}
            return result

    with patch.object(parent.unicorn, "Uc", ObservedMachine):
        trace = parent.run(program, native, frame)
    return trace, offsets, final
