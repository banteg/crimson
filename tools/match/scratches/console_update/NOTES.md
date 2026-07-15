# `console_update`

Native target: `crimsonland.exe` at `0x00401a40` (904 bytes).

Live callsites load `console_log_queue` into `ECX` and pass no stack
arguments, proving this is `console_queue_t::update()` rather than the former
flat one-argument signature. The method eases the console slide from the
per-frame delta, polls text input while open, distinguishes Ctrl+Up/Down log
scrolling from history navigation, handles cursor and page keys, completes
cvars or commands on Tab, and prepends distinct submitted lines to history
before executing them.

The recovered method compiles to the same 296-instruction extent with all 63
static references resolved. The remaining 89.19% residual is register-save
placement: native VC6 delays the `ESI`/`EDI` saves until the cursor-editing
tail, while the current source saves `ESI` at entry and releases `EDI` before
the submission branch. No volatile state, dummy dependency, or artificial
control flow is used to force that schedule.

The callsites of `console_tokenize_line` likewise preserve the queue in `ECX`;
recording it as a member call leaves both its own 55-instruction scratch and
the 90-instruction `console_exec_line` scratch exact.
