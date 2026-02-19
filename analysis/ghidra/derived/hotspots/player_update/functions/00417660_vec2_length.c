/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: vec2_length */
/* function_mapped: vec2_length */
/* address: 0x00417660 */
/* byte_range: [486268, 486428) */
/* vec2_length @ 00417660 */

/* returns sqrt(x*x + y*y) for a 2-float vector */

float vec2_length(float *v)

{
  return SQRT(v[1] * v[1] + *v * *v);
}
