/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: vec2_add_inplace */
/* function_mapped: vec2_add_inplace */
/* address: 0x0041e400 */
/* byte_range: [608148, 608376) */
/* vec2_add_inplace @ 0041e400 */

/* adds delta XY into pos; unused param_1 in decompile */

void vec2_add_inplace(int unused, float *pos, float *delta)

{
  *pos = *pos + *delta;
  pos[1] = delta[1] + pos[1];
  return;
}
