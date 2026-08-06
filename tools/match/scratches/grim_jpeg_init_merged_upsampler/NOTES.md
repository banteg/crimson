# Residual

The official IJG 6a initializer compiled with the archive-backed MSVC 7 profile
matches 34 of 35 instructions. The native object clears byte-sized
`need_context_rows` before publishing `start_pass`, while the local compiler
emits the two independent stores in source order and uses `mov 0`. This scratch
remains non-exact rather than forcing that store schedule in the source.
