// musl's sources include <features.h> only for `hidden`, which math.c defines. glibc's and wasi-libc's own
// headers need theirs, so this shim defers to it where one exists (macOS has none).
#pragma once
#if __has_include_next(<features.h>)
#include_next <features.h>
#endif
