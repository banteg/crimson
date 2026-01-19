# In-game console (tilde)

Crimsonland includes a developer-style console that appears in-game and accepts
commands and cvar assignments. This page summarizes the static findings that
back the tilde/backquote console behavior.

## Open / close (runtime)

- The console is toggled in-game with the tilde/backquote key (`~` / `` ` ``).
- We have not yet mapped the exact hotkey handler in the input code, but the
  console input path is fully identified (see below).

## Input handling (static)

- Text input is polled via Grim2D `get_key_char` (vtable `+0x50`) in
  `console_input_poll` (`0x00401060`).
- Enter (`0x0d`) sets `console_input_ready` and NUL-terminates the buffer.
- Backspace (`0x08`) deletes one char.
- The input buffer is capped at `0x3ff` chars.

Relevant globals (see `analysis/ghidra/maps/data_map.json`):
- `console_input_enabled` (`0x0047f4d4`)
- `console_input_ready` (`0x0047ea58`)
- `console_input_buffer` (`0x0047e448`) + length (`0x0047ea54`)
- `console_prompt_string` (`0x004712c0`, prompt format `"> %s"`)

## Command / cvar dispatch (static)

`console_exec_line` (`0x00401940`) tokenizes the input and then:

1) If the first token matches a cvar, it either:
   - Prints current value when invoked with no value.
   - Updates the value when called with exactly one argument (parses float and
     stores both string + float).
2) Else if the token matches a command, it calls the command handler.
3) Otherwise it prints `Unknown command "%s"`.

The cvar paths emit:
- `"%s" is "%s" (%ff)`
- `"%s" set to "%s" (%ff)`

## Built-in commands (static registration)

`console_init` (`0x00401560`) registers the core commands below. The handlers
are not fully named yet, but the strings and registration are confirmed:

- `cmdlist` (`0x00471244`)
- `vars` (`0x0047123c`)
- `set` (`0x00471230`)
- `echo` (`0x00471234`)
- `quit` (`0x00471228`)
- `clear` (`0x00471220`)
- `extendconsole` (`0x00471210`)
- `minimizeconsole` (`0x00471200`)
- `exec` (`0x004711f8`)

Additional help strings exist for:
- `exec <script>`
- `set <var> <value>`
- `"%i commands"` / `"%i variables"`

## Scripts and logs

- `exec` is used to run scripts such as `autoexec.txt` and
  `music\\game_tunes.txt`.
- Console output can be flushed to `console.log` via `console_flush_log`
  (`0x00402860`), which uses `game_build_path` to resolve the filename.

## Open questions

- Where is the tilde hotkey check wired (input polling vs. UI state)?
- What exactly do `extendconsole` and `minimizeconsole` control (height,
  history window, or draw mode)?
