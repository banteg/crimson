# console_cmd_open_url

Native target: `crimsonland.exe` at `0x0042a890` (151 bytes).

The handler requires one URL argument, converts it into a 260-element UTF-16
stack buffer with `MultiByteToWideChar`, and passes it to
`HlinkNavigateString`. Negative HRESULTs print a failure message; successful
launches echo the original multibyte URL.

Natural Win32 source matches all 43 instructions, full prefix, with all
fourteen references aligned.
