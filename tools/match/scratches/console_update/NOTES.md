# `console_update`

Native target: `crimsonland.exe` at `0x00401a40` (904 bytes).

Live callsites load `console_log_queue` into `ECX` and pass no stack
arguments, proving this is `console_queue_t::update()` rather than the former
flat one-argument signature. The method eases the console slide from the
per-frame delta, polls text input while open, distinguishes Ctrl+Up/Down log
scrolling from history navigation, handles cursor and page keys, completes
cvars or commands on Tab, and prepends distinct submitted lines to history
before executing them.

The native non-submission path also calls `console_input_buffer()` immediately
before polling Enter, even though the returned buffer pointer is not consumed.
Restoring that observed accessor call raises the result from 89.19% to 90.05%,
reduces the weighted gap from 97.73 to 89.94 bytes, and resolves its 64th
static reference. The candidate now has 297 instructions against 296 native
instructions because of the remaining save-placement residual.

Native VC6 delays the `ESI`/`EDI` saves until the cursor-editing tail, while
the current source saves `ESI` at entry and releases `EDI` before the
submission branch. That extra early save accounts for the candidate's one
extra instruction and shifts otherwise corresponding control-flow labels. No
volatile state, dummy dependency, or artificial control flow is used to force
that schedule.

The callsites of `console_tokenize_line` likewise preserve the queue in `ECX`;
recording it as a member call leaves both its own 55-instruction scratch and
the 90-instruction `console_exec_line` scratch exact.
