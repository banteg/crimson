/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: vec2_add */
/* function_mapped: vec2_add */
/* address: 0x0041e270 */
/* byte_range: [605576, 605748) */
/* vec2_add @ 0041e270 */

/* adds delta xy into dst */

void vec2_add(float *dst, float *delta)

{
  *dst = *dst + *delta;
  dst[1] = delta[1] + dst[1];
  return;
}
