/* WORK COPY: creature_apply_damage */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* creature_apply_damage @ 004207c0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* applies damage + impulse, handles death side effects; returns 1 when killed */

int creature_apply_damage(int creature_id, float damage, int damage_type, float *impulse)

{
  float heading_jitter;
  float impulse_y;
  int perk_count;
  uint rng_value;
  int scale_roll;
  int living_fortress_scan_count;
  int debris_spawn_count;
  float *living_fortress_timer_ptr;
  
  (&creature_pool)[creature_id].hit_flash_timer = 0.2;
  /* Damage-type 1 path: stack perk modifiers before touching health. */
  if (damage_type == 1) {
    perk_count = perk_count_get(perk_id_uranium_filled_bullets);
    if (perk_count != 0) {
      damage = damage + damage;
    }
    perk_count = perk_count_get(perk_id_living_fortress);
    if ((perk_count != 0) && (0 < _config_player_count)) {
      living_fortress_timer_ptr = &player_state_table.living_fortress_timer;
      living_fortress_scan_count = _config_player_count;
      do {
        if (0.0 < living_fortress_timer_ptr[-0x20]) {
          damage = (*living_fortress_timer_ptr * 0.05 + 1.0) * damage;
        }
        living_fortress_timer_ptr = living_fortress_timer_ptr + 0xd8;
        living_fortress_scan_count = living_fortress_scan_count + -1;
      } while (living_fortress_scan_count != 0);
    }
    perk_count = perk_count_get(perk_id_barrel_greaser);
    if (perk_count != 0) {
      damage = damage * 1.4;
    }
    perk_count = perk_count_get(perk_id_doctor);
    if (perk_count != 0) {
      damage = damage * 1.2;
    }
    /* Non-heavy targets receive a randomized heading kick when hit. */
    if (((&creature_pool)[creature_id].flags & 4) == 0) {
      rng_value = crt_rand();
      heading_jitter = ((float)(int)((rng_value & 0x7f) - 0x40) * 0.002) /
                       ((&creature_pool)[creature_id].size * 0.025);
      if (1.5707964 < heading_jitter) {
        heading_jitter = 1.5707964;
      }
      (&creature_pool)[creature_id].heading =
           heading_jitter + (&creature_pool)[creature_id].heading;
    }
  }
  /* Damage-type 7 path: ion-gun mastery multiplier. */
  else if ((damage_type == 7) &&
          (perk_count = perk_count_get(perk_id_ion_gun_master), perk_count != 0)) {
    damage = damage * 1.2;
  }
  /* Already-dead targets only advance their lifecycle stage each frame. */
  if ((&creature_pool)[creature_id].health <= 0.0) {
    (&creature_pool)[creature_id].lifecycle_stage =
         (&creature_pool)[creature_id].lifecycle_stage - frame_dt * 15.0;
  }
  else {
    /* Live target path: optional fire bonus, then health + knockback apply. */
    if ((damage_type == 4) &&
       (perk_count = perk_count_get(perk_id_pyromaniac), perk_count != 0)) {
      damage = damage * 1.5;
      crt_rand();
    }
    (&creature_pool)[creature_id].health = (&creature_pool)[creature_id].health - damage;
    (&creature_pool)[creature_id].vel_x = (&creature_pool)[creature_id].vel_x - *impulse;
    (&creature_pool)[creature_id].vel_y = (&creature_pool)[creature_id].vel_y - impulse[1];
    if ((&creature_pool)[creature_id].health <= 0.0) {
      /* Lethal resolution: death bookkeeping plus type-dependent death SFX/FX. */
      (&creature_pool)[creature_id].lifecycle_stage =
           (&creature_pool)[creature_id].lifecycle_stage - frame_dt;
      creature_handle_death(creature_id,true);
      impulse_y = impulse[1];
      (&creature_pool)[creature_id].vel_x =
           (&creature_pool)[creature_id].vel_x - (*impulse + *impulse);
      (&creature_pool)[creature_id].vel_y =
           (&creature_pool)[creature_id].vel_y - (impulse_y + impulse_y);
      if (((&creature_pool)[creature_id].flags & 0x10) == 0) {
        rng_value = crt_rand();
        rng_value = rng_value & 0x80000003;
        if ((int)rng_value < 0) {
          rng_value = (rng_value - 1 | 0xfffffffc) + 1;
        }
        sfx_play_panned((float)creature_type_table[(&creature_pool)[creature_id].type_id].sfx_bank_a
                               [rng_value]);
      }
      else {
        /* Armored death branch spawns five tinted debris effects. */
        _effect_template_color_r = 0x3f4ccccd;
        _effect_template_flags = 0x1d;
        _effect_template_color_g = 0x3f4ccccd;
        _effect_template_color_b = 0x3e99999a;
        _effect_template_color_a = 0x3f000000;
        _effect_template_lifetime = 0x3f333333;
        _effect_template_half_width = 0x42100000;
        _effect_template_half_height = 0x42100000;
        debris_spawn_count = 5;
        do {
          rng_value = crt_rand();
          _effect_template_rotation = (float)(rng_value & 0x7f) * 0.049087387;
          rng_value = crt_rand();
          effect_template_vel_x = (float)(int)((rng_value & 0x7f) - 0x40);
          rng_value = crt_rand();
          effect_template_vel_y = (float)(int)((rng_value & 0x7f) - 0x40);
          scale_roll = crt_rand();
          _effect_template_scale_step = (float)(scale_roll % 0x8c) * 0.01 + 0.3;
          effect_spawn(0,&(&creature_pool)[creature_id].pos_x);
          debris_spawn_count = debris_spawn_count + -1;
        } while (debris_spawn_count != 0);
      }
    }
  }
  if (0.0 < (&creature_pool)[creature_id].health) {
    return 0;
  }
  return 1;
}
