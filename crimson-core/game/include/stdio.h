#pragma once
#include_next <stdio.h>
// The platform layer opens files by their Windows paths; game.py points the
// recovered fopen calls here.
#ifdef __cplusplus
extern "C"
#endif
    FILE *
    platform_fopen(const char *path, const char *mode);
