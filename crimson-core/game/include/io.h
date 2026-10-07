#pragma once
#include <stddef.h>
#include <time.h>
// The MSVC CRT's directory search, which the platform layer implements.
struct _finddata_t {
  unsigned attrib;
  time_t time_create;
  time_t time_access;
  time_t time_write;
  unsigned long size;
  char name[260];
};
