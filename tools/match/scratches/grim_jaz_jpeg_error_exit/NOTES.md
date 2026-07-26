# `grim_jaz_jpeg_error_exit`

Exact 41-byte, 14-instruction match with MSVC 6.5 `/O2 /GB /MD`.

The field layout is the IJG libjpeg 6b API used elsewhere in the decoder:
`format_message` is callback slot 3, `JMSG_LENGTH_MAX` is 200, the base
`jpeg_error_mgr` is 132 bytes, and the following field is a `jmp_buf`. The
callback formats the current message and jumps to the decoder recovery point.

The IDA function extent stops immediately after the imported `longjmp` call,
but the native byte at `0x10004eb8` is the compiler-emitted unreachable
`pop esi`. `END=0x10004eb9` includes that byte and makes the full compiler
output exact; the following bytes are alignment NOPs.
