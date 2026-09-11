import shutil
import subprocess
from pathlib import Path

import pytest


def test_frida_records_fixed_g_query_as_held_replay_bit() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to exercise the Frida capture functions")
    source = (Path(__file__).parents[2] / "scripts/frida/gameplay_diff_capture.js").read_text()
    constants = source[source.index("const REPLAY_FIRE_DOWN_FLAG") : source.index("const CONFIG_PARSE_ERRORS")]
    pack = source[source.index("function packReplayInputFlags(") : source.index("function replayInputsFromIntentRows(")]
    empty = source[source.index("function buildEmptyPlayerKeyState(") : source.index("function isPlayerUpdateCaller(")]
    update = source[source.index("function updatePlayerInputKeyState(") : source.index("function makeTickContext(")]
    harness = '''
const assert = require("node:assert/strict");
const tick = {
  before: { input_bindings: { players: [{ fire: 104 }, { fire: 105 }], reload: 90 } },
  input_player_keys: [],
};
updatePlayerInputKeyState(tick, "grim_is_key_active", 0x22, true, null);
for (const row of tick.input_player_keys) {
  assert.equal(row.fire_bullets_key_down, true);
  assert.equal(row.fire_down, false);
  assert.equal(packReplayInputFlags(row) & (1 << 17), 1 << 17);
}
// A later false query must not erase a true observation in the same native tick.
updatePlayerInputKeyState(tick, "grim_is_key_active", 0x22, false, null);
assert.equal(tick.input_player_keys[0].fire_bullets_key_down, true);
// A new tick starts with no held-key evidence. Press edges do not grant the cheat.
tick.input_player_keys = [];
updatePlayerInputKeyState(tick, "grim_is_key_pressed", 0x22, true, null);
for (const row of tick.input_player_keys) {
  assert.equal(row.fire_bullets_key_down, false);
  assert.equal(packReplayInputFlags(row) & (1 << 17), 0);
}
updatePlayerInputKeyState(tick, "grim_is_key_down", 0x22, true, null);
assert.equal(tick.input_player_keys[0].fire_bullets_key_down, true);
'''
    result = subprocess.run([node, "-e", constants + pack + empty + update + harness], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
