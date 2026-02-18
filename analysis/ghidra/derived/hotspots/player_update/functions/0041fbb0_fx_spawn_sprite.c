/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: fx_spawn_sprite */
/* function_mapped: fx_spawn_sprite */
/* address: 0x0041fbb0 */
/* byte_range: [637728, 638775) */
/* fx_spawn_sprite @ 0041fbb0 */

/* spawns a sprite effect entry in DAT_00496820 */

int fx_spawn_sprite(float *pos, float *vel, float scale)

{
  sprite_effect_t *psVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  psVar1 = &sprite_effect_pool;
  do {
    if ((char)psVar1->active == '\0') goto LAB_0041fbd8;
    psVar1 = psVar1 + 1;
    iVar3 = iVar3 + 1;
  } while ((int)psVar1 < 0x49aa20);
  iVar3 = crt_rand();
  iVar3 = iVar3 % 0x180;
LAB_0041fbd8:
  *(undefined1 *)&(&sprite_effect_pool)[iVar3].active = 1;
  (&sprite_effect_pool)[iVar3].color_b = 1.0;
  (&sprite_effect_pool)[iVar3].color_g = 1.0;
  (&sprite_effect_pool)[iVar3].color_r = 1.0;
  (&sprite_effect_pool)[iVar3].color_a = 1.0;
  (&sprite_effect_pool)[iVar3].pos_x = *pos;
  (&sprite_effect_pool)[iVar3].pos_y = pos[1];
  (&sprite_effect_pool)[iVar3].vel_x = *vel;
  (&sprite_effect_pool)[iVar3].vel_y = vel[1];
  (&sprite_effect_pool)[iVar3].scale = scale;
  iVar2 = crt_rand();
  (&sprite_effect_pool)[iVar3].rotation = (float)(iVar2 % 0x274) * 0.01;
  return iVar3;
}
