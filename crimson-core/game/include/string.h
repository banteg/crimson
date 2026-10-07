#pragma once
#include_next <string.h>
// The MSVC CRT's case-insensitive comparisons.
#ifdef __cplusplus
extern "C" {
#endif
int _stricmp(const char *a, const char *b);
int _strnicmp(const char *a, const char *b, size_t count);
#ifdef __cplusplus
}
#endif
