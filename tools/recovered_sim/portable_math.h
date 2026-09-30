#pragma once
#include <math.h>
#include <stdint.h>
#include <string.h>
extern "C" {
double portable_sin(double);
double portable_cos(double);
double portable_atan2(double, double);
double portable_pow(double, double);
float portable_crt_pow_pc24(double, double);
float portable_sinf(float);
float portable_cosf(float);
double portable_atan2f(float, float);
}

// First x87 PC24 arithmetic operation, preserving the wide transcendental
// operand.
inline float portable_mul32(double x, double y) { return (float)(x * y); }

// PC24 rounds the significand while retaining x87's exponent range. All
// intermediates in the normalize seam fit normal doubles. A float cast alone
// misses double rounding when a later F32 store produces a subnormal.
inline double portable_round_pc24(double value) {
  uint64_t bits;
  memcpy(&bits, &value, sizeof(bits));
  if ((bits & UINT64_C(0x7ff0000000000000)) == UINT64_C(0x7ff0000000000000))
    return value;
  constexpr uint64_t mask = (UINT64_C(1) << 29) - 1;
  uint64_t remainder = bits & mask;
  bits &= ~mask;
  if (remainder > (UINT64_C(1) << 28) ||
      (remainder == (UINT64_C(1) << 28) && (bits & (UINT64_C(1) << 29))))
    bits += UINT64_C(1) << 29;
  memcpy(&value, &bits, sizeof(bits));
  return value;
}
