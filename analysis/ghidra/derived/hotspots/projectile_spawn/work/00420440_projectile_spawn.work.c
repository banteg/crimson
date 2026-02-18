/* WORK COPY: projectile_spawn */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* projectile_spawn @ 00420440 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* allocates a projectile slot, initializes fields, and returns the index (overrides to type 0x2d
   when Fire Bullets is active) */

int __cdecl projectile_spawn(float *pos,float angle,projectile_type_id_t type_id,int owner_id)

{
  projectile_t *projectile_slot_ptr;
  int projectile_slot_idx;
  float10 cos_component;
  float10 sin_component;
  
  /* Owner-class and timer gate for Fire Bullets rewrite (with shots-fired side effect). */
  if ((char)bonus_spawn_guard == '\0') {
    while (((((owner_id == -100 || (owner_id == -1)) || (owner_id == -2)) || (owner_id == -3)) &&
           ((_highscore_record_shots_fired = _highscore_record_shots_fired + 1,
            type_id != PROJECTILE_TYPE_FIRE_BULLETS &&
            ((0.0 < player_state_table.fire_bullets_timer || (0.0 < player2_fire_bullets_timer))))))
          ) {
      type_id = PROJECTILE_TYPE_FIRE_BULLETS;
    }
  }
  /* First-fit scan: use first inactive slot, otherwise reuse terminal slot 0x5f. */
  projectile_slot_idx = 0;
  projectile_slot_ptr = projectile_pool;
  do {
    if (projectile_slot_ptr->active == '\0') goto LAB_004204d7;
    projectile_slot_ptr = projectile_slot_ptr + 1;
    projectile_slot_idx = projectile_slot_idx + 1;
  } while ((int)projectile_slot_ptr < 0x493eb8);
  projectile_slot_idx = 0x5f;
LAB_004204d7:
  /* Shared spawn initialization before per-type hit-radius/damage-pool tuning. */
  cos_component = (float10)fcos((float10)angle);
  projectile_pool[projectile_slot_idx].pos.tail.vy.owner_id = owner_id;
  projectile_pool[projectile_slot_idx].active = '\x01';
  projectile_pool[projectile_slot_idx].pos.tail.vy.base_damage = (&weapon_table)[type_id].projectile_meta;
  projectile_pool[projectile_slot_idx].pos_x = *pos;
  projectile_pool[projectile_slot_idx].pos.pos_y = pos[1];
  projectile_pool[projectile_slot_idx].pos.origin_x = *pos;
  projectile_pool[projectile_slot_idx].pos.tail.origin_y = pos[1];
  projectile_pool[projectile_slot_idx].angle = angle;
  projectile_pool[projectile_slot_idx].pos.tail.vy.type_id = type_id;
  projectile_pool[projectile_slot_idx].pos.tail.vy.life_timer = 0.4;
  projectile_pool[projectile_slot_idx].pos.tail.vy.reserved = 0.0;
  projectile_pool[projectile_slot_idx].pos.tail.vy.speed_scale = 1.0;
  projectile_pool[projectile_slot_idx].pos.tail.vel_x = (float)(cos_component * (float10)1.5);
  sin_component = (float10)fsin((float10)angle);
  projectile_pool[projectile_slot_idx].pos.tail.vy.vel_y = (float)(sin_component * (float10)1.5);
  if (type_id == PROJECTILE_TYPE_ION_MINIGUN) {
    projectile_pool[projectile_slot_idx].pos.tail.vy.hit_radius = 3.0;
    projectile_pool[projectile_slot_idx].pos.tail.vy.damage_pool = 1.0;
    return projectile_slot_idx;
  }
  if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
    projectile_pool[projectile_slot_idx].pos.tail.vy.hit_radius = 5.0;
    projectile_pool[projectile_slot_idx].pos.tail.vy.damage_pool = 1.0;
    return projectile_slot_idx;
  }
  /* Large plasma/cannon rounds get radius 10.0; most others default to radius 1.0. */
  if ((type_id == PROJECTILE_TYPE_ION_CANNON) || (type_id == PROJECTILE_TYPE_PLASMA_CANNON)) {
    projectile_pool[projectile_slot_idx].pos.tail.vy.hit_radius = 10.0;
  }
  else {
    projectile_pool[projectile_slot_idx].pos.tail.vy.hit_radius = 1.0;
    if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
      projectile_pool[projectile_slot_idx].pos.tail.vy.damage_pool = 300.0;
      return projectile_slot_idx;
    }
    if (type_id == PROJECTILE_TYPE_FIRE_BULLETS) {
      projectile_pool[projectile_slot_idx].pos.tail.vy.damage_pool = 240.0;
      return projectile_slot_idx;
    }
    if (type_id == PROJECTILE_TYPE_BLADE_GUN) {
      projectile_pool[projectile_slot_idx].pos.tail.vy.damage_pool = 50.0;
      return projectile_slot_idx;
    }
  }
  projectile_pool[projectile_slot_idx].pos.tail.vy.damage_pool = 1.0;
  return projectile_slot_idx;
}
