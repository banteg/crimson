/* WORK COPY: bonus_try_spawn_on_kill */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* bonus_try_spawn_on_kill @ 0041f8d0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* decides whether to drop a bonus on kill (mode/perk rules) and spawns pickup burst */

void bonus_try_spawn_on_kill(float *kill_pos_ptr)

{
  int iVar1;
  bonus_entry_t *spawned_bonus_ptr;
  bonus_entry_t *bonus_scan_ptr;
  uint rng_value;
  int effect_scale_rand;
  
  if (config_game_mode == GAME_MODE_TYPO_SHOOTER) {
    return;
  }
  if (demo_mode_active != '\0') {
    return;
  }
  if (config_game_mode == GAME_MODE_RUSH) {
    return;
  }
  if (config_game_mode == GAME_MODE_TUTORIAL) {
    return;
  }
  if (((player_state_table.weapon_id == 1) ||
      ((player2_weapon_id == 1 && (_config_player_count == 2)))) &&
     (iVar1 = crt_rand(), ((byte)iVar1 & 3) < 3)) {
    spawned_bonus_ptr = bonus_spawn_at_pos(kill_pos_ptr);
    spawned_bonus_ptr->bonus_id = BONUS_ID_WEAPON;
    iVar1 = weapon_pick_random_available();
    (spawned_bonus_ptr->time).amount = iVar1;
    if (iVar1 == 1) {
      iVar1 = weapon_pick_random_available();
      (spawned_bonus_ptr->time).amount = iVar1;
    }
    iVar1 = 0;
    if (spawned_bonus_ptr->bonus_id != BONUS_ID_POINTS) {
      bonus_scan_ptr = bonus_pool;
      do {
        if (bonus_scan_ptr->bonus_id == spawned_bonus_ptr->bonus_id) {
          iVar1 = iVar1 + 1;
        }
        bonus_scan_ptr = bonus_scan_ptr + 1;
      } while ((int)bonus_scan_ptr < 0x482b08);
      if (1 < iVar1) goto LAB_0041f998;
    }
    if (((spawned_bonus_ptr->time).amount == 1) ||
       (iVar1 = perk_count_get(perk_id_my_favourite_weapon), iVar1 != 0)) {
LAB_0041f998:
      spawned_bonus_ptr->bonus_id = BONUS_ID_NONE;
      return;
    }
  }
  else {
    iVar1 = crt_rand();
    if ((iVar1 % 9 != 1) &&
       ((player_state_table.weapon_id != 1 || (iVar1 = crt_rand(), iVar1 % 5 != 1)))) {
      iVar1 = perk_count_get(perk_id_bonus_magnet);
      if (iVar1 == 0) {
        return;
      }
      iVar1 = crt_rand();
      if (iVar1 % 10 != 2) {
        return;
      }
    }
    spawned_bonus_ptr = bonus_spawn_at_pos(kill_pos_ptr);
    if ((spawned_bonus_ptr->bonus_id == BONUS_ID_WEAPON) &&
       (SQRT((kill_pos_ptr[1] - player_state_table.pos_y) * (kill_pos_ptr[1] - player_state_table.pos_y) +
             (*kill_pos_ptr - player_state_table.pos_x) * (*kill_pos_ptr - player_state_table.pos_x)) < 56.0)) {
      spawned_bonus_ptr->bonus_id = BONUS_ID_POINTS;
      (spawned_bonus_ptr->time).amount = 100;
    }
    iVar1 = 0;
    if (spawned_bonus_ptr->bonus_id != BONUS_ID_POINTS) {
      bonus_scan_ptr = bonus_pool;
      do {
        if (bonus_scan_ptr->bonus_id == spawned_bonus_ptr->bonus_id) {
          iVar1 = iVar1 + 1;
        }
        bonus_scan_ptr = bonus_scan_ptr + 1;
      } while ((int)bonus_scan_ptr < 0x482b08);
      if (1 < iVar1) goto LAB_0041fa76;
    }
    if ((spawned_bonus_ptr->time).amount == player_state_table.weapon_id) {
LAB_0041fa76:
      spawned_bonus_ptr->bonus_id = BONUS_ID_NONE;
      return;
    }
  }
  if ((spawned_bonus_ptr != (bonus_entry_t *)0x0) && (spawned_bonus_ptr != &bonus_pool_sentinel)) {
    _effect_template_color_r = 0x3ecccccd;
    _effect_template_flags = 0x1d;
    _effect_template_color_g = 0x3f000000;
    _effect_template_color_b = 0x3f800000;
    _effect_template_color_a = 0x3f000000;
    _effect_template_lifetime = 0x3f000000;
    _effect_template_half_width = 0x42000000;
    _effect_template_half_height = 0x42000000;
    iVar1 = 0x10;
    do {
      rng_value = crt_rand();
      _effect_template_rotation = (float)(rng_value & 0x7f) * 0.049087387;
      rng_value = crt_rand();
      rng_value = rng_value & 0x8000007f;
      if ((int)rng_value < 0) {
        rng_value = (rng_value - 1 | 0xffffff80) + 1;
      }
      effect_template_vel_x = (float)(int)(rng_value - 0x40);
      rng_value = crt_rand();
      rng_value = rng_value & 0x8000007f;
      if ((int)rng_value < 0) {
        rng_value = (rng_value - 1 | 0xffffff80) + 1;
      }
      effect_template_vel_y = (float)(int)(rng_value - 0x40);
      effect_scale_rand = crt_rand();
      _effect_template_scale_step = (float)(effect_scale_rand % 100) * 0.01 + 0.1;
      effect_spawn(0,kill_pos_ptr);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return;
}
