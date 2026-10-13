// Stands in for <math.h> while host/math.c compiles musl's sources (musl/src), so they never meet another
// libc's declarations (glibc's math.h declares musl's internal __sin and __cos with other signatures). Every
// routine is static: none of them replaces a libm symbol for the rest of the program.
#pragma once
typedef double double_t;
typedef float float_t;
#define INFINITY __builtin_inff()
#define NAN __builtin_nanf("")
#define isnan(x) __builtin_isnan(x)
#define fabs(x) __builtin_fabs(x)
#define floor(x) __builtin_floor(x)
#define scalbn(x, n) __builtin_scalbn(x, n)
static double sin(double);
static double cos(double);
static double atan(double);
static double atan2(double, double);
static double pow(double, double);
static double log2(double);
