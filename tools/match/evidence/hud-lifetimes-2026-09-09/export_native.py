"""Run with bn py --script; emits native ESP facts for simple ESP memory operands."""

import hashlib
import re

f = function("ui_render_hud")  # noqa: F821
rows = []
for tokens, address in sorted(f.instructions, key=lambda row: row[1]):
    assembly = "".join(str(token) for token in tokens)
    if not re.search(r"\[esp(?:\+0x[0-9a-f]+)?\]", assembly):
        continue
    value = f.get_reg_value_at(address, "esp")
    if value.type.name != "StackFrameOffset":
        raise ValueError(f"non-concrete ESP at {address:#x}; full function analysis is required")
    rows.append([address - f.start, value.value])
result = {
    "schema": 1,
    "function": "ui_render_hud",
    "start": f.start,
    "body_sha256": hashlib.sha256(bv.read(f.start, 7081)).hexdigest(),  # noqa: F821
    "provider": "Binary Ninja get_reg_value_at(address, esp), StackFrameOffset",
    "instruction_offsets_and_entry_esp": rows,
}
