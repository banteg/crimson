/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: fx_spawn_secondary_projectile */
/* function_mapped: fx_spawn_secondary_projectile */
/* address: 0x00420360 */
/* byte_range: [649407, 651186) */
/* fx_spawn_secondary_projectile @ 00420360 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns a typed entry in DAT_00495ad8 (secondary projectile pool) */

int __cdecl
fx_spawn_secondary_projectile(float *pos,float angle,secondary_projectile_type_id_t type_id)

{
  secondary_projectile_t *psVar1;
  int iVar2;
  int iVar3;
  float10 fVar4;
  float10 fVar5;
  
  iVar3 = 0;
  psVar1 = secondary_projectile_pool;
  do {
    if (psVar1->active == '\0') goto LAB_0042037f;
    psVar1 = psVar1 + 1;
    iVar3 = iVar3 + 1;
  } while ((int)psVar1 < 0x4965d8);
  iVar3 = 0x3f;
LAB_0042037f:
  _highscore_record_shots_fired = _highscore_record_shots_fired + 1;
  fVar4 = (float10)fcos((float10)angle - (float10)1.5707964);
  secondary_projectile_pool[iVar3].active = '\x01';
  secondary_projectile_pool[iVar3].pos_x = *pos;
  secondary_projectile_pool[iVar3].pos.pos_y = pos[1];
  secondary_projectile_pool[iVar3].life_timer = 2.0;
  secondary_projectile_pool[iVar3].angle = angle;
  secondary_projectile_pool[iVar3].pos.vx.vy.trail_timer = 0.0;
  secondary_projectile_pool[iVar3].pos.vx.vy.type_id = type_id;
  secondary_projectile_pool[iVar3].pos.vx.vel_x = (float)(fVar4 * (float10)90.0);
  fVar5 = (float10)fsin((float10)angle - (float10)1.5707964);
  secondary_projectile_pool[iVar3].pos.vx.vy.vel_y = (float)(fVar5 * (float10)90.0);
  if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
    iVar2 = creature_find_nearest(&(&player_state_table)[render_overlay_player_index].aim_x,-1,0.0);
    secondary_projectile_pool[iVar3].pos.vx.vy.target_id = iVar2;
    secondary_projectile_pool[iVar3].pos.vx.vel_x = (float)fVar4 * 190.0;
    secondary_projectile_pool[iVar3].pos.vx.vy.vel_y = (float)fVar5 * 190.0;
  }
  return iVar3;
}
