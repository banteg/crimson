/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: fx_queue_add */
/* function_mapped: fx_queue_add */
/* address: 0x0041e840 */
/* byte_range: [607805, 608819) */
/* fx_queue_add @ 0041e840 */

/* pushes a quad entry into DAT_004aaf18 (capped at 0x80); returns 1 on success */

int fx_queue_add(int effect_id, float *pos, float w, float h, float rotation, float *rgba)

{
  fx_queue_entry_t *pfVar1;
  int iVar2;
  int iVar3;
  uint3 uVar4;
  int iVar5;
  
  iVar2 = fx_queue_count;
  iVar3 = fx_queue_count * 0x28;
  iVar5 = fx_queue_count + 1;
  (&fx_queue)[fx_queue_count].pos_x = *pos;
  (&fx_queue)[fx_queue_count].pos_y = pos[1];
  (&fx_queue)[fx_queue_count].color_r = *rgba;
  (&fx_queue)[fx_queue_count].color_g = rgba[1];
  (&fx_queue)[fx_queue_count].color_b = rgba[2];
  pfVar1 = &fx_queue + fx_queue_count;
  fx_queue_count = iVar5;
  pfVar1->color_a = rgba[3];
  (&fx_queue)[iVar2].width = w;
  (&fx_queue)[iVar2].height = h;
  (&fx_queue)[iVar2].rotation = rotation;
  (&fx_queue)[iVar2].effect_id = effect_id;
  uVar4 = (uint3)((uint)iVar3 >> 8);
  if (0x7f < iVar5) {
    fx_queue_count = 0x7f;
    return (uint)uVar4 << 8;
  }
  return CONCAT31(uVar4,1);
}
