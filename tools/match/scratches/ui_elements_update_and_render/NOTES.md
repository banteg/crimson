# `ui_elements_update_and_render`

Native target: `crimsonland.exe` at `0x0041a530` (409 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 103/103
normalized instructions, full prefix, and masked references `41/0/0`.

Live Binary Ninja shows the top-level UI transition coordinator. It sets the
UI renderer mode, advances or rewinds the shared timeline while the console is
closed, commits the pending game state at zero, and clamps completed forward
transitions to the greatest active element timeline. Outside gameplay it then
walks all 41 UI elements in reverse order, updating and rendering each one,
before restoring the global color and blend/config state.

The zero-angle assignment to the Crimson sign is represented as the small
ordinary inline rotation helper implied by the native `cos`/`sin` sequence.
Storing cosine before evaluating sine naturally preserves the native VC6 x87
stack schedule.
No inline assembly, volatile state, dummy references, or dead expressions are
used.
