/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: vec2_normalize_dispatch */
/* function_mapped: vec2_normalize_dispatch */
/* address: 0x00452f2a */
/* byte_range: [1797448, 1798017) */
/* vec2_normalize_dispatch @ 00452f2a */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* hot-path thunk: jmp [DAT_00479658] after lazy init; used by player_update, projectile_update, and
   creature_update_all callsites */

float * vec2_normalize_dispatch(float *dst,float *src)

{
  float *pfVar1;
  
                    /* WARNING: Could not recover jumptable at 0x00452f2a. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pfVar1 = (float *)(*_DAT_00479658)();
  return pfVar1;
}



/*
