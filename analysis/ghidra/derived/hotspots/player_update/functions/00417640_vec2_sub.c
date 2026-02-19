/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: vec2_sub */
/* function_mapped: vec2_sub */
/* address: 0x00417640 */
/* byte_range: [485909, 486264) */
/* vec2_sub @ 00417640 */

/* [binja] float* __thiscall sub_417640(float* arg1, float* arg2, float* arg3) */

float * vec2_sub(float *arg1, float *arg2, float *arg3)

{
  float fVar1;
  float fVar2;
  
  fVar1 = *(float *)((int)this + 4);
  fVar2 = arg2[1];
  *arg1 = *(float *)this - *arg2;
  arg1[1] = fVar1 - fVar2;
  return arg1;
}
