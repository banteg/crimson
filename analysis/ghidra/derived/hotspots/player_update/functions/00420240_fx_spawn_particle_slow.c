/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: fx_spawn_particle_slow */
/* function_mapped: fx_spawn_particle_slow */
/* address: 0x00420240 */
/* byte_range: [648029, 649403) */
/* fx_spawn_particle_slow @ 00420240 */

/* spawns a slow particle entry in DAT_00493eb8 */

int fx_spawn_particle_slow(float *pos, float angle)

{
  particle_t *ppVar1;
  int iVar2;
  uint uVar3;
  float10 fVar4;
  
  ppVar1 = &particle_pool;
  uVar3 = 0;
  do {
    if (ppVar1->active == '\0') goto LAB_00420270;
    ppVar1 = ppVar1 + 1;
    uVar3 = uVar3 + 1;
  } while ((int)ppVar1 < 0x495ab8);
  uVar3 = crt_rand();
  uVar3 = uVar3 & 0x8000007f;
  if ((int)uVar3 < 0) {
    uVar3 = (uVar3 - 1 | 0xffffff80) + 1;
  }
LAB_00420270:
  fVar4 = (float10)fcos((float10)angle);
  (&particle_pool)[uVar3].active = '\x01';
  (&particle_pool)[uVar3].pos_x = *pos;
  (&particle_pool)[uVar3].pos_y = pos[1];
  (&particle_pool)[uVar3].vel_x = (float)(fVar4 * (float10)30.0);
  fVar4 = (float10)fsin((float10)angle);
  (&particle_pool)[uVar3].vel_y = (float)(fVar4 * (float10)30.0);
  (&particle_pool)[uVar3].intensity = 1.0;
  (&particle_pool)[uVar3].scale_x = 1.0;
  (&particle_pool)[uVar3].scale_y = 1.0;
  (&particle_pool)[uVar3].scale_z = 1.0;
  (&particle_pool)[uVar3].age = 0.0;
  (&particle_pool)[uVar3].angle = angle;
  iVar2 = crt_rand();
  (&particle_pool)[uVar3].spin = (float)(iVar2 % 0x274) * 0.01;
  (&particle_pool)[uVar3].render_flag = '\x01';
  *(undefined1 *)&(&particle_pool)[uVar3].style_id = 8;
  (&particle_pool)[uVar3].target_id = -1;
  return uVar3;
}
