# console_exec_line

Native target: `crimsonland.exe` at `0x00401940` (254 bytes).

The queue tokenizes the line, looks up both a cvar and a command, and gives the
cvar path priority. Two-token cvar input replaces the owned string and cached
float; other arities query the current value. Echo output is conditional, while
command callbacks and unknown-command reporting are unconditional.

The member has no coherent returned value: terminal paths leave unrelated
values from the argument count, echo flag, callback, or formatted output in the
return registers. Recovering it as `void` restores the plausible source ABI.
Assigning the CRT conversion directly to the float and reusing that expression
for echo output reproduces the native live x87 value. The result matches all 90
instructions, full prefix, with all nineteen references aligned.
