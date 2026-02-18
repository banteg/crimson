/* source: analysis/ghidra/raw/crimsonland.exe_functions.json + Binary Ninja disasm */
/* function_original: thunk_FUN_00452f1d */
/* function_mapped: vec2_normalize_dispatch */
/* address: 0x00452f2a */
/* byte_range: manual-thunk */
/* manual supplement until regenerated decompiled export includes thunk bodies */

extern float *(*DAT_00479658)(float *dst, float *src);

/* tail thunk: jmp [DAT_00479658] */
float *vec2_normalize_dispatch(float *dst, float *src)

{
  return (*DAT_00479658)(dst, src);
}
