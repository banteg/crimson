#pragma once
#include <math.h>
extern "C" {
double portable_sin(double);
double portable_cos(double);
double portable_atan2(double, double);
double portable_pow(double, double);
float portable_sinf(float);
float portable_cosf(float);
double portable_atan2f(float, float);
}

// First x87 PC24 arithmetic operation, preserving the wide transcendental
// operand.
inline float portable_mul32(double x, double y) { return (float)(x * y); }
