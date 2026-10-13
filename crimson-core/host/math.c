// The portable numerical helpers. musl 1.2.5's double routines (musl/, verbatim) build into this one translation
// unit on every target, so no result depends on the host libm, and with __FP_FAST_FMA off pow and log2 take the
// same unfused path on aarch64 as on x86-64 and wasm.
#undef __FP_FAST_FMA
#define hidden __attribute__((__visibility__("hidden")))
// A libc linked beside this one (wasi-libc is musl) has its own copies of musl's internal symbols.
#define __math_divzero portable_musl_math_divzero
#define __math_invalid portable_musl_math_invalid
#define __math_oflow portable_musl_math_oflow
#define __math_uflow portable_musl_math_uflow
#define __math_xflow portable_musl_math_xflow
#define __rem_pio2_large portable_musl_rem_pio2_large
#define __rem_pio2 portable_musl_rem_pio2
#define __sin portable_musl_sin
#define __cos portable_musl_cos
#define __exp_data portable_musl_exp_data
#define __pow_log_data portable_musl_pow_log_data
#define __log2_data portable_musl_log2_data
#include "musl/src/math/__math_divzero.c"
#include "musl/src/math/__math_invalid.c"
#include "musl/src/math/__math_oflow.c"
#include "musl/src/math/__math_uflow.c"
#include "musl/src/math/__math_xflow.c"
#include "musl/src/math/__rem_pio2_large.c"
#include "musl/src/math/__rem_pio2.c"
#include "musl/src/math/__sin.c"
#include "musl/src/math/__cos.c"
#include "musl/src/math/sin.c"
#include "musl/src/math/cos.c"
#include "musl/src/math/atan.c"
#include "musl/src/math/atan2.c"
// The data files and pow.c reuse table macro names.
#include "musl/src/math/exp_data.c"
#undef N
#include "musl/src/math/pow_data.c"
#undef N
#undef A
#include "musl/src/math/pow.c"
#undef T
#undef A
#undef N
#undef OFF
#include "musl/src/math/log2_data.c"
#undef N
#undef A
#undef B
#include "musl/src/math/log2.c"

double portable_sin(double x) { return sin(x); }
double portable_cos(double x) { return cos(x); }
double portable_atan2(double y, double x) { return atan2(y, x); }
double portable_pow(double x, double y) { return pow(x, y); }
float portable_sinf(float x) { return (float)sin(x); }
float portable_cosf(float x) { return (float)cos(x); }
double portable_atan2f(float y, float x) { return atan2(y, x); }

// Positive finite bases: CRT __CIpow / crt_two_to_tos under gameplay PC24.
// FYL2X and F2XM1 stay wide; FSUB and FADD round to a 24-bit mantissa.
float portable_crt_pow_pc24(double base, double exponent) {
  double scaled_log = exponent * log2(base);
  double whole = __builtin_rint(scaled_log);  // FRNDINT, round to nearest even
  float fraction = (float)(scaled_log - whole);
  float mantissa = (float)(pow(2.0, fraction) - 1.0 + 1.0);
  return __builtin_ldexpf(mantissa, (int)whole);
}
