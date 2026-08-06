# Residual

The official IJG 6a controller compiled with the archive-backed MSVC 7 profile
matches 70 of 71 instructions. The only code residual is the byte-sized
`spare_full` clear after copying a saved row: the native object uses `and 0`,
while the local compiler emits `mov 0`. The operation and all surrounding
control flow are equivalent; this scratch remains non-exact.
