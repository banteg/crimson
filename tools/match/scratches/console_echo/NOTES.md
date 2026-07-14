# console_echo

Native target: `crimsonland.exe` at `0x00401410` (245 bytes).

The command treats a sole `off` or `on` argument as an echo-state change;
otherwise it prints arguments 1 onward separated by spaces and terminates the
line. The native inlined `strcmp` order shows the literals are the left
operands. Preserving that source order matches all 93 instructions and
references `17/0/0`.
