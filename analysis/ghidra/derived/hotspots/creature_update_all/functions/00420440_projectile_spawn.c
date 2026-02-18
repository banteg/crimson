/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: projectile_spawn */
/* function_mapped: projectile_spawn */
/* address: 0x00420440 */
/* byte_range: [651765, 654777) */
/* projectile_spawn @ 00420440 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* allocates a projectile slot, initializes fields, and returns the index (overrides to type 0x2d
   when Fire Bullets is active) */

int __cdecl projectile_spawn(float *pos,float angle,projectile_type_id_t type_id,int owner_id)

{
  projectile_t *ppVar1;
  int iVar2;
  float10 fVar3;
  
  if ((char)bonus_spawn_guard == '\0') {
    while (((((owner_id == -100 || (owner_id == -1)) || (owner_id == -2)) || (owner_id == -3)) &&
           ((_highscore_record_shots_fired = _highscore_record_shots_fired + 1,
            type_id != PROJECTILE_TYPE_FIRE_BULLETS &&
            ((0.0 < player_state_table.fire_bullets_timer || (0.0 < player2_fire_bullets_timer))))))
          ) {
      type_id = PROJECTILE_TYPE_FIRE_BULLETS;
    }
  }
  iVar2 = 0;
  ppVar1 = projectile_pool;
  do {
    if (ppVar1->active == '\0') goto LAB_004204d7;
    ppVar1 = ppVar1 + 1;
    iVar2 = iVar2 + 1;
  } while ((int)ppVar1 < 0x493eb8);
  iVar2 = 0x5f;
LAB_004204d7:
  fVar3 = (float10)fcos((float10)angle);
  projectile_pool[iVar2].pos.tail.vy.owner_id = owner_id;
  projectile_pool[iVar2].active = '\x01';
  projectile_pool[iVar2].pos.tail.vy.base_damage = (&weapon_table)[type_id].projectile_meta;
  projectile_pool[iVar2].pos_x = *pos;
  projectile_pool[iVar2].pos.pos_y = pos[1];
  projectile_pool[iVar2].pos.origin_x = *pos;
  projectile_pool[iVar2].pos.tail.origin_y = pos[1];
  projectile_pool[iVar2].angle = angle;
  projectile_pool[iVar2].pos.tail.vy.type_id = type_id;
  projectile_pool[iVar2].pos.tail.vy.life_timer = 0.4;
  projectile_pool[iVar2].pos.tail.vy.reserved = 0.0;
  projectile_pool[iVar2].pos.tail.vy.speed_scale = 1.0;
  projectile_pool[iVar2].pos.tail.vel_x = (float)(fVar3 * (float10)1.5);
  fVar3 = (float10)fsin((float10)angle);
  projectile_pool[iVar2].pos.tail.vy.vel_y = (float)(fVar3 * (float10)1.5);
  if (type_id == PROJECTILE_TYPE_ION_MINIGUN) {
    projectile_pool[iVar2].pos.tail.vy.hit_radius = 3.0;
    projectile_pool[iVar2].pos.tail.vy.damage_pool = 1.0;
    return iVar2;
  }
  if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
    projectile_pool[iVar2].pos.tail.vy.hit_radius = 5.0;
    projectile_pool[iVar2].pos.tail.vy.damage_pool = 1.0;
    return iVar2;
  }
  if ((type_id == PROJECTILE_TYPE_ION_CANNON) || (type_id == PROJECTILE_TYPE_PLASMA_CANNON)) {
    projectile_pool[iVar2].pos.tail.vy.hit_radius = 10.0;
  }
  else {
    projectile_pool[iVar2].pos.tail.vy.hit_radius = 1.0;
    if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
      projectile_pool[iVar2].pos.tail.vy.damage_pool = 300.0;
      return iVar2;
    }
    if (type_id == PROJECTILE_TYPE_FIRE_BULLETS) {
      projectile_pool[iVar2].pos.tail.vy.damage_pool = 240.0;
      return iVar2;
    }
    if (type_id == PROJECTILE_TYPE_BLADE_GUN) {
      projectile_pool[iVar2].pos.tail.vy.damage_pool = 50.0;
      return iVar2;
    }
  }
  projectile_pool[iVar2].pos.tail.vy.damage_pool = 1.0;
  return iVar2;
}
