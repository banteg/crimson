/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: fx_queue_add_random */
/* function_mapped: fx_queue_add_random */
/* address: 0x00427700 */
/* byte_range: [791231, 792573) */
/* fx_queue_add_random @ 00427700 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns a random fx_queue_add entry (effect ids 3..7) with grayscale color/size */

void fx_queue_add_random(float *pos)

{
  uint uVar1;
  int iVar2;
  float *pos_00;
  float w;
  float h;
  float rotation;
  float *rgba;
  float local_8;
  float local_4;
  
  if (config_fx_toggle == '\0') {
    if (((byte)fx_queue_random_init_flags & 1) == 0) {
      fx_queue_random_init_flags._0_1_ = (byte)fx_queue_random_init_flags | 1;
      _fx_queue_random_color_r = 0.9;
      _fx_queue_random_color_g = 0.9;
      _fx_queue_random_color_b = 0.9;
      _fx_queue_random_color_a = 0x3f47ae14;
      crt_atexit(&DAT_00427830);
    }
    uVar1 = crt_rand();
    _fx_queue_random_color_r = (float)(uVar1 & 0xf) * 0.01 + 0.84;
    _fx_queue_random_color_g = _fx_queue_random_color_r;
    _fx_queue_random_color_b = _fx_queue_random_color_r;
    iVar2 = crt_rand();
    w = (float)(iVar2 % 0x18 + -0xc) + 30.0;
    iVar2 = crt_rand();
    rgba = (float *)&fx_queue_random_color_r;
    rotation = (float)(iVar2 % 0x274) * 0.01;
    local_8 = *pos - w * 0.5;
    local_4 = pos[1] - w * 0.5;
    pos_00 = &local_8;
    h = w;
    iVar2 = crt_rand();
    fx_queue_add(iVar2 % 5 + 3,pos_00,w,h,rotation,rgba);
  }
  return;
}
