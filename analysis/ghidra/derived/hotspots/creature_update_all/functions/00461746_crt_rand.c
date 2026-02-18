/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: crt_rand */
/* function_mapped: crt_rand */
/* address: 0x00461746 */
/* byte_range: [2023347, 2023645) */
/* crt_rand @ 00461746 */

/* returns a pseudo-random value using the per-thread seed (rand) */

int crt_rand(void)

{
  DWORD *pDVar1;
  uint uVar2;
  
  pDVar1 = crt_get_thread_data();
  uVar2 = pDVar1[5] * 0x343fd + 0x269ec3;
  pDVar1[5] = uVar2;
  return uVar2 >> 0x10 & 0x7fff;
}



/*
