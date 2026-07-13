/* WORK COPY: projectile_update */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* projectile_update @ 00420b90 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* updates projectile movement, collisions, and hit effects. Runtime capture (2026-02-06
   gameplay_state_capture): dominant sfx_play_panned cluster is 54/51/53/55/52/50. */

void projectile_update(void)

{
  float *pfVar1;
  float fVar2;
  char particle_kind;
  projectile_type_id_t projectile_type;
  secondary_projectile_type_id_t secondary_type;
  float fVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  float fVar11;
  int iVar12;
  float *pfVar13;
  secondary_projectile_vel_y_block_t *secondary_proj_ptr;
  float10 fVar15;
  float10 fVar16;
  float10 fVar17;
  float10 fVar18;
  float10 fVar19;
  float10 fVar20;
  float10 fVar21;
  longlong lVar22;
  float fVar23;
  int loop_idx;
  int slot_idx;
  int plasma_ring_idx;
  float local_dc;
  int spray_max_offset;
  float substep_dx;
  float substep_dy;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  float local_58;
  float fStack_50;
  float local_4c;
  float local_48;
  float local_44;
  float fStack_40;
  float local_3c;
  float fStack_38;
  float local_34;
  float fStack_30;
  float local_2c;
  float local_28;
  float local_20;
  float local_1c;
  float fStack_18;
  float local_14;
  float local_10 [4];
  
  /* Frame-level scalar setup for ion-family projectile tuning. */
  projectile_update_tick = projectile_update_tick + 1;
  local_c0 = 1.0;
  iVar7 = perk_count_get(perk_id_ion_gun_master);
  if (iVar7 != 0) {
    local_c0 = 1.2;
  }
  /* Primary projectile pool sweep. */
  slot_idx = 0;
  do {
    if (projectile_pool[slot_idx].active != '\0') {
      /* Lifetime + bounds gates before expensive collision stepping. */
      if (projectile_pool[slot_idx].pos.tail.vy.life_timer <= 0.0) {
        projectile_pool[slot_idx].active = '\0';
      }
      if (0.4 <= projectile_pool[slot_idx].pos.tail.vy.life_timer) {
        pfVar13 = &projectile_pool[slot_idx].pos_x;
        if ((((projectile_pool[slot_idx].pos_x < -64.0) ||
             (projectile_pool[slot_idx].pos.pos_y < -64.0)) ||
            ((float)(_terrain_texture_width + 0x40) < *pfVar13)) ||
           ((float)(_terrain_texture_height + 0x40) < projectile_pool[slot_idx].pos.pos_y)) {
LAB_004219ef:
          fVar11 = projectile_pool[slot_idx].pos.tail.vy.life_timer - frame_dt;
LAB_004219f8:
          projectile_pool[slot_idx].pos.tail.vy.life_timer = fVar11;
        }
        else {
          lVar22 = __ftol();
          local_dc = (float)lVar22;
          fVar20 = (float10)projectile_pool[slot_idx].angle - (float10)1.5707964;
          fVar15 = (float10)fcos(fVar20);
          fVar21 = (float10)frame_dt;
          fVar16 = (float10)fsin(fVar20);
          fVar20 = (float10)frame_dt;
          iVar7 = perk_count_get(perk_id_barrel_greaser);
          if ((iVar7 != 0) && (projectile_pool[slot_idx].pos.tail.vy.owner_id < 0)) {
            lVar22 = __ftol();
            local_dc = (float)lVar22;
          }
          substep_dy = 0.0;
          substep_dx = 0.0;
          local_c4 = 0.0;
          /* Integrate in coarse substeps and resolve hit targets along the swept path. */
          if (0 < (int)local_dc) {
            do {
              fVar11 = local_c4;
              substep_dx = (float)(fVar15 * fVar21 * (float10)20.0) *
                         projectile_pool[slot_idx].pos.tail.vy.speed_scale * 3.0 + substep_dx;
              substep_dy = (float)(fVar16 * fVar20 * (float10)20.0) *
                         projectile_pool[slot_idx].pos.tail.vy.speed_scale * 3.0 + substep_dy;
              if ((4.0 <= SQRT(substep_dy * substep_dy + substep_dx * substep_dx)) ||
                 ((int)local_dc <= (int)local_c4 + 3)) {
                vec2_add(pfVar13,&substep_dx);
                iVar7 = creature_find_in_radius
                                  (pfVar13,projectile_pool[slot_idx].pos.tail.vy.hit_radius,0);
                if ((iVar7 == -1) || (iVar7 == projectile_pool[slot_idx].pos.tail.vy.owner_id)) {
                  if (slot_idx != shock_chain_projectile_id) {
                    iVar12 = projectile_pool[slot_idx].pos.tail.vy.owner_id;
                    if (iVar12 != -100) {
                      iVar7 = player_find_in_radius
                                        (iVar12,pfVar13,
                                         projectile_pool[slot_idx].pos.tail.vy.hit_radius);
                    }
                    if (iVar7 != -1) {
                      projectile_pool[slot_idx].pos.tail.vy.life_timer = 0.25;
                      if ((&player_state_table)[iVar7].shield_timer <= 0.0) {
                        (&player_state_table)[iVar7].health =
                             (&player_state_table)[iVar7].health - 10.0;
                      }
                    }
                  }
                }
                else {
                  iVar12 = perk_count_get(perk_id_poison_bullets);
                  if ((iVar12 != 0) && (iVar12 = crt_rand(), ((byte)iVar12 & 7) == 1)) {
                    (&creature_pool)[iVar7].flags = (&creature_pool)[iVar7].flags | 1;
                  }
                  /* Projectile-type-specific hit FX and special behavior. */
                  projectile_type = projectile_pool[slot_idx].pos.tail.vy.type_id;
                  if (projectile_type == PROJECTILE_TYPE_BLADE_GUN) {
                    iVar12 = 8;
                    do {
                      fVar11 = 0.0;
                      uVar10 = crt_rand();
                      effect_spawn_blood_splatter
                                (pfVar13,(float)(uVar10 & 0xff) * 0.024543693,fVar11);
                      iVar12 = iVar12 + -1;
                    } while (iVar12 != 0);
                  }
                  else if (projectile_type == PROJECTILE_TYPE_SPLITTER_GUN) {
                    effect_spawn_splitter_hit_burst(pfVar13,26.0,3);
                    projectile_spawn(pfVar13,projectile_pool[slot_idx].angle - 1.0471976,
                                     PROJECTILE_TYPE_SPLITTER_GUN,iVar7);
                    projectile_spawn(pfVar13,projectile_pool[slot_idx].angle + 1.0471976,
                                     PROJECTILE_TYPE_SPLITTER_GUN,iVar7);
                  }
                  local_64 = 0x3f800000;
                  local_68 = 1.0;
                  _effect_template_color_g = 0x3f800000;
                  local_60 = 0x3f800000;
                  local_5c = 0x3f800000;
                  _effect_template_color_r = 0x3f800000;
                  _effect_template_flags = 0x59;
                  _effect_template_color_b = 0x3f800000;
                  _effect_template_color_a = 0x3f800000;
                  _effect_template_lifetime = 0x3eb33333;
                  _effect_template_age = 0;
                  _effect_template_half_width = 0x40800000;
                  _effect_template_half_height = 0x40800000;
                  if (config_violence_disabled == '\0') {
                    iVar12 = perk_count_get(perk_id_bloody_mess_quick_learner);
                    if (iVar12 == 0) {
                      if (bonus_freeze_timer <= 0.0) {
                        iVar12 = 2;
                        do {
                          effect_spawn_blood_splatter
                                    (pfVar13,projectile_pool[slot_idx].angle - 1.5707964,0.0);
                          iVar9 = crt_rand();
                          if (((byte)iVar9 & 7) == 2) {
                            effect_spawn_blood_splatter
                                      (pfVar13,(projectile_pool[slot_idx].angle - 1.5707964) +
                                               3.1415927,0.0);
                          }
                          iVar12 = iVar12 + -1;
                        } while (iVar12 != 0);
                      }
                    }
                    else {
                      iVar12 = 8;
                      do {
                        fVar11 = 0.0;
                        uVar10 = crt_rand();
                        effect_spawn_blood_splatter
                                  (pfVar13,(projectile_pool[slot_idx].angle - 1.5707964) +
                                           (float)(int)((uVar10 & 0x1f) - 0x10) * 0.0625,fVar11);
                        iVar12 = iVar12 + -1;
                      } while (iVar12 != 0);
                      effect_spawn_blood_splatter
                                (pfVar13,(projectile_pool[slot_idx].angle - 1.5707964) + 3.1415927,
                                 0.0);
                    }
                  }
                  if ((&creature_pool)[iVar7].lifecycle_stage == 16.0) {
                    _highscore_record_shots_hit = _highscore_record_shots_hit + 1;
                  }
                  iVar12 = perk_count_get(perk_id_bloody_mess_quick_learner);
                  if (iVar12 != 0) {
                    spray_max_offset = 0x1e;
                    iVar12 = -0x1e;
                    do {
                      iVar9 = spray_max_offset - iVar12;
                      iVar8 = crt_rand();
                      local_58 = (float)(iVar8 % iVar9 + iVar12);
                      iVar8 = crt_rand();
                      local_20 = local_58 + (&creature_pool)[iVar7].pos_x;
                      local_1c = (float)(iVar8 % iVar9 + iVar12) + (&creature_pool)[iVar7].pos_y;
                      fx_queue_add_random(&local_20);
                      iVar8 = crt_rand();
                      local_28 = (float)(iVar8 % iVar9 + iVar12);
                      iVar8 = crt_rand();
                      local_48 = local_28 + (&creature_pool)[iVar7].pos_x;
                      local_44 = (float)(iVar8 % iVar9 + iVar12) + (&creature_pool)[iVar7].pos_y;
                      fx_queue_add_random(&local_48);
                      iVar12 = iVar12 + -10;
                      spray_max_offset = spray_max_offset + 10;
                    } while (-0x3c < iVar12);
                  }
                  projectile_type = projectile_pool[slot_idx].pos.tail.vy.type_id;
                  if (((projectile_type != PROJECTILE_TYPE_FIRE_BULLETS) &&
                      (projectile_type != PROJECTILE_TYPE_GAUSS_GUN)) && (projectile_type != PROJECTILE_TYPE_BLADE_GUN))
                  {
                    projectile_pool[slot_idx].pos.tail.vy.life_timer = 0.25;
                    uVar10 = crt_rand();
                    fVar17 = (float10)projectile_pool[slot_idx].angle - (float10)1.5707964;
                    fVar18 = (float10)fcos(fVar17);
                    *pfVar13 = (float)(fVar18 * (float10)(uVar10 & 3) + (float10)*pfVar13);
                    fVar17 = (float10)fsin(fVar17);
                    projectile_pool[slot_idx].pos.pos_y =
                         (float)(fVar17 * (float10)(uVar10 & 3) +
                                (float10)projectile_pool[slot_idx].pos.pos_y);
                  }
                  fVar11 = projectile_pool[slot_idx].pos.origin_x - *pfVar13;
                  fVar23 = projectile_pool[slot_idx].pos.tail.origin_y -
                           projectile_pool[slot_idx].pos.pos_y;
                  fVar11 = SQRT(fVar11 * fVar11 + fVar23 * fVar23);
                  if (fVar11 < 50.0) {
                    fVar11 = 50.0;
                  }
                  projectile_type = projectile_pool[slot_idx].pos.tail.vy.type_id;
                  fVar23 = (&weapon_table)[projectile_type].damage_scale;
                  if (projectile_type == PROJECTILE_TYPE_ION_MINIGUN) {
                    effect_spawn_ion_hit_core(pfVar13,1.5,0.1);
                    effect_spawn_ion_hit_sparks(pfVar13,0.8);
                  }
                  else if (projectile_type == PROJECTILE_TYPE_ION_RIFLE) {
                    if ((0 < shock_chain_links_left) && (slot_idx == shock_chain_projectile_id)) {
                      shock_chain_links_left = shock_chain_links_left + -1;
                      iVar12 = creature_find_nearest(pfVar13,iVar7,100.0);
                      bonus_spawn_guard._0_1_ = 1;
                      fVar17 = (float10)fpatan((float10)(&creature_pool)[iVar12].pos_y -
                                               (float10)(&creature_pool)[iVar7].pos_y,
                                               (float10)(&creature_pool)[iVar12].pos_x -
                                               (float10)(&creature_pool)[iVar7].pos_x);
                      shock_chain_projectile_id =
                           projectile_spawn(pfVar13,(float)((fVar17 - (float10)1.5707964) -
                                                           (float10)3.1415927),
                                            PROJECTILE_TYPE_ION_RIFLE,iVar7);
                      bonus_spawn_guard._0_1_ = 0;
                    }
                    effect_spawn_ion_hit_core(pfVar13,1.2,0.4);
                    effect_spawn_ion_hit_sparks(pfVar13,1.2);
                  }
                  else if (projectile_type == PROJECTILE_TYPE_ION_CANNON) {
                    effect_spawn_ion_hit_core(pfVar13,1.0,1.0);
                    effect_spawn_ion_hit_sparks(pfVar13,2.2);
                    sfx_play_panned(sfx_shockwave);
                  }
                  else if (projectile_type == PROJECTILE_TYPE_PLASMA_CANNON) {
                    bonus_spawn_guard._0_1_ = 1;
                    plasma_ring_idx = 0;
                    fVar6 = (&creature_pool)[iVar7].size * 0.5 + 1.0;
                    do {
                      fVar2 = (float)((float10)plasma_ring_idx * (float10)0.5235988);
                      fVar17 = (float10)fcos((float10)plasma_ring_idx * (float10)0.5235988);
                      fVar18 = (float10)fsin((float10)fVar2);
                      local_34 = (float)(fVar18 * (float10)fVar6);
                      local_88 = (float)(fVar17 * (float10)fVar6 + (float10)*pfVar13);
                      local_84 = local_34 + projectile_pool[slot_idx].pos.pos_y;
                      projectile_spawn(&local_88,fVar2,PROJECTILE_TYPE_PLASMA_RIFLE,-100);
                      plasma_ring_idx = plasma_ring_idx + 1;
                    } while (plasma_ring_idx < 0xc);
                    bonus_spawn_guard._0_1_ = 0;
                    sfx_play_panned(sfx_explosion_medium);
                    sfx_play_panned(sfx_shockwave);
                    effect_spawn_plasma_hit_core(pfVar13,1.5,1.0);
                    effect_spawn_plasma_hit_core(pfVar13,1.0,1.0);
                  }
                  else if (projectile_type == PROJECTILE_TYPE_SHRINKIFIER) {
                    effect_spawn_shrinkifier_hit(pfVar13);
                    fVar6 = (&creature_pool)[iVar7].size * 0.65;
                    projectile_pool[slot_idx].pos.tail.vy.life_timer = 0.25;
                    (&creature_pool)[iVar7].size = fVar6;
                    if (fVar6 < 16.0) {
                      creature_handle_death(iVar7,true);
                    }
                  }
                  else if (projectile_type == PROJECTILE_TYPE_PULSE_GUN) {
                    local_14 = substep_dy * 3.0;
                    (&creature_pool)[iVar7].pos_x = substep_dx * 3.0 + (&creature_pool)[iVar7].pos_x;
                    (&creature_pool)[iVar7].pos_y = local_14 + (&creature_pool)[iVar7].pos_y;
                  }
                  else if (projectile_type == PROJECTILE_TYPE_PLAGUE_SPREADER) {
                    (&creature_pool)[iVar7].collision_flag = '\x01';
                  }
                  /* Damage pool accounting and impact response on the struck creature. */
                  fVar11 = ((100.0 / fVar11) * fVar23 * 30.0 + 10.0) * 0.95;
                  if ((0.0 < fVar11) && (0.0 < (&creature_pool)[iVar7].health)) {
                    fVar23 = projectile_pool[slot_idx].pos.tail.vy.damage_pool - 1.0;
                    projectile_pool[slot_idx].pos.tail.vy.damage_pool = fVar23;
                    fVar17 = (float10)fcos((float10)projectile_pool[slot_idx].angle -
                                           (float10)1.5707964);
                    fVar18 = fVar17 * (float10)projectile_pool[slot_idx].pos.tail.vy.speed_scale;
                    if (fVar23 <= 0.0) {
                      local_98 = (float)fVar18;
                      local_94 = (float)(fVar17 * (float10)projectile_pool[slot_idx].pos.tail.vy.
                                                           speed_scale);
                      creature_apply_damage(iVar7,fVar11,1,&local_98);
                      if (projectile_pool[slot_idx].pos.tail.vy.life_timer != 0.25) {
                        projectile_pool[slot_idx].pos.tail.vy.life_timer = 0.25;
                      }
                    }
                    else {
                      local_78 = (float)fVar18;
                      local_74 = (float)(fVar17 * (float10)projectile_pool[slot_idx].pos.tail.vy.
                                                           speed_scale);
                      creature_apply_damage(iVar7,fVar23,1,&local_78);
                      projectile_pool[slot_idx].pos.tail.vy.damage_pool =
                           projectile_pool[slot_idx].pos.tail.vy.damage_pool -
                           (&creature_pool)[iVar7].health;
                    }
                  }
                  if ((projectile_pool[slot_idx].pos.tail.vy.damage_pool == 1.0) &&
                     (fVar11 = projectile_pool[slot_idx].pos.tail.vy.life_timer,
                     projectile_pool[slot_idx].pos.tail.vy.damage_pool = 0.0, fVar11 != 0.25)) {
                    projectile_pool[slot_idx].pos.tail.vy.life_timer = 0.25;
                  }
                  (&creature_pool)[iVar7].state_flag = '\x01';
                  crt_rand();
                  projectile_type = projectile_pool[slot_idx].pos.tail.vy.type_id;
                  if ((projectile_type == PROJECTILE_TYPE_GAUSS_GUN) ||
                     (projectile_type == PROJECTILE_TYPE_FIRE_BULLETS)) {
                    perk_count_get(perk_id_bloody_mess_quick_learner);
                    loop_idx = 6;
                    do {
                      iVar12 = crt_rand();
                      fVar17 = (float10)(iVar12 % 100) * (float10)0.1;
                      if ((float10)4.0 < fVar17) {
                        iVar12 = crt_rand();
                        fVar17 = (float10)(iVar12 % 0x5a + 10) * (float10)0.1;
                      }
                      if ((float10)7.0 < fVar17) {
                        iVar12 = crt_rand();
                        fVar17 = (float10)(iVar12 % 0x50 + 0x14) * (float10)0.1;
                      }
                      fVar18 = (float10)projectile_pool[slot_idx].angle - (float10)1.5707964;
                      fVar19 = (float10)fcos(fVar18);
                      local_a8 = 0.0;
                      local_a4 = 0.0;
                      fVar11 = (float)(fVar19 * fVar17 * (float10)20.0);
                      fVar18 = (float10)fsin(fVar18);
                      fVar23 = (float)(fVar18 * fVar17 * (float10)20.0);
                      local_b0 = fVar11 + (&creature_pool)[iVar7].pos_x;
                      local_ac = fVar23 + (&creature_pool)[iVar7].pos_y;
                      vec2_add_inplace(iVar7,&local_b0,&local_a8);
                      crt_rand();
                      if (0.0 < bonus_freeze_timer) {
                        local_a0 = fVar11 + *pfVar13;
                        local_9c = fVar23 + projectile_pool[slot_idx].pos.pos_y;
                        iVar12 = crt_rand();
                        effect_spawn_freeze_shard
                                  (&local_a0,
                                   (projectile_pool[slot_idx].angle - 1.5707964) +
                                   (float)(iVar12 % 100) * 0.01);
                      }
                      local_b8 = fVar11 + (&creature_pool)[iVar7].pos_x;
                      local_b4 = fVar23 + (&creature_pool)[iVar7].pos_y;
                      fx_queue_add_random(&local_b8);
                      loop_idx = loop_idx + -1;
                    } while (loop_idx != 0);
                  }
                  else if (bonus_freeze_timer <= 0.0) {
                    pfVar1 = &(&creature_pool)[iVar7].pos_x;
                    iVar12 = 3;
                    do {
                      iVar9 = crt_rand();
                      fVar18 = ((float10)projectile_pool[slot_idx].angle - (float10)1.5707964) +
                               (float10)(iVar9 % 0x14 + -10) * (float10)0.1;
                      fVar17 = (float10)fcos(fVar18);
                      fVar11 = (float)(fVar17 * (float10)20.0);
                      fVar17 = (float10)fsin(fVar18);
                      fVar23 = (float)(fVar17 * (float10)20.0);
                      fx_queue_add_random(pfVar1);
                      local_4c = fVar23 * 1.5;
                      local_70 = fVar11 * 1.5 + *pfVar1;
                      local_6c = local_4c + (&creature_pool)[iVar7].pos_y;
                      fx_queue_add_random(&local_70);
                      local_3c = fVar23 + fVar23;
                      local_80 = fVar11 + fVar11 + *pfVar1;
                      local_7c = local_3c + (&creature_pool)[iVar7].pos_y;
                      fx_queue_add_random(&local_80);
                      local_2c = fVar23 * 2.5;
                      local_90 = fVar11 * 2.5 + *pfVar1;
                      local_8c = local_2c + (&creature_pool)[iVar7].pos_y;
                      fx_queue_add_random(&local_90);
                      iVar12 = iVar12 + -1;
                    } while (iVar12 != 0);
                  }
                  else {
                    iVar7 = crt_rand();
                    effect_spawn_freeze_shard
                              (pfVar13,(projectile_pool[slot_idx].angle - 1.5707964) +
                                       (float)(iVar7 % 100) * 0.01);
                  }
                  if (((demo_mode_active == '\0') && (music_playlist_randomized_latch == '\0')) &&
                     (config_game_mode != GAME_MODE_RUSH)) {
                    sfx_play_exclusive(music_track_extra_0);
                  }
                  else {
                    fVar11 = sfx_shock_hit_01;
                    if ((&weapon_ammo_class)[projectile_pool[slot_idx].pos.tail.vy.type_id * 0x1f]
                        != 4) {
                      iVar7 = crt_rand();
                      fVar11 = (float)(iVar7 % 6 + sfx_bullet_hit_01);
                    }
                    sfx_play_panned(fVar11);
                  }
                  fVar11 = local_c4;
                  if (projectile_pool[slot_idx].pos.tail.vy.damage_pool <= 0.0) break;
                }
                substep_dy = 0.0;
                substep_dx = 0.0;
              }
              local_c4 = (float)((int)fVar11 + 3);
            } while ((int)local_c4 < (int)local_dc);
          }
        }
      }
      else {
        /* Expiring ion/gauss projectiles still emit radius damage while decaying. */
        projectile_type = projectile_pool[slot_idx].pos.tail.vy.type_id;
        if ((projectile_type == PROJECTILE_TYPE_ION_RIFLE) || (projectile_type == PROJECTILE_TYPE_ION_MINIGUN)) {
          if (slot_idx == shock_chain_projectile_id) {
            shock_chain_projectile_id = -1;
            shock_chain_links_left = 0;
          }
          projectile_pool[slot_idx].pos.tail.vy.life_timer =
               projectile_pool[slot_idx].pos.tail.vy.life_timer - frame_dt;
          if (projectile_type == PROJECTILE_TYPE_ION_RIFLE) {
            fVar23 = frame_dt * 100.0;
            fVar11 = local_c0 * 88.0;
          }
          else {
            fVar23 = frame_dt * 40.0;
            fVar11 = local_c0 * 60.0;
          }
        }
        else {
          if (projectile_type != PROJECTILE_TYPE_ION_CANNON) {
            if (projectile_type != PROJECTILE_TYPE_GAUSS_GUN) goto LAB_004219ef;
            fVar11 = projectile_pool[slot_idx].pos.tail.vy.life_timer - frame_dt * 0.1;
            goto LAB_004219f8;
          }
          projectile_pool[slot_idx].pos.tail.vy.life_timer =
               projectile_pool[slot_idx].pos.tail.vy.life_timer - frame_dt * 0.7;
          fVar23 = frame_dt * 300.0;
          fVar11 = local_c0 * 128.0;
        }
        creatures_apply_radius_damage(&projectile_pool[slot_idx].pos_x,fVar11,fVar23,7);
      }
    }
    slot_idx = slot_idx + 1;
  } while (slot_idx < 0x60);
  /* Secondary projectile pool: rockets, seekers, and explosion lifecycles. */
  secondary_proj_ptr = &secondary_projectile_pool[0].pos.vx.vy;
  do {
    if (*(char *)((int)(secondary_proj_ptr + -2) + 0x10) != '\0') {
      if (secondary_proj_ptr->type_id == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
        camera_shake_pulses = 4;
        fVar11 = frame_dt * 3.0 + *(float *)((int)(secondary_proj_ptr + -1) + 0x10);
        *(float *)((int)(secondary_proj_ptr + -1) + 0x10) = fVar11;
        if (1.0 < fVar11) {
          fVar11 = secondary_proj_ptr->vel_y * 256.0;
          local_10[0] = 0.0;
          local_10[1] = 0.0;
          local_10[2] = 0.0;
          local_10[3] = 0.25;
          fx_queue_add(0x10,(float *)((int)(secondary_proj_ptr + -1) + 8),fVar11,fVar11,0.0,local_10);
          *(undefined1 *)((int)(secondary_proj_ptr + -2) + 0x10) = 0;
        }
        fVar11 = secondary_proj_ptr->vel_y;
        fVar23 = *(float *)((int)(secondary_proj_ptr + -1) + 0x10);
        iVar7 = 0;
        pfVar13 = &creature_pool.pos_y;
        do {
          if ((((creature_t *)(pfVar13 + -6))->active != '\0') && (0.0 < pfVar13[3])) {
            fVar6 = pfVar13[-1] - *(float *)((int)(secondary_proj_ptr + -1) + 8);
            fVar2 = *pfVar13 - *(float *)((int)(secondary_proj_ptr + -1) + 0xc);
            if (SQRT(fVar6 * fVar6 + fVar2 * fVar2) < fVar11 * fVar23 * 80.0) {
              local_c0 = fVar6;
              local_bc = fVar2;
              vec2_normalize_dispatch(&local_c0,&local_c0);
              local_b8 = local_c0 * 0.1;
              local_b4 = local_bc * 0.1;
              creature_apply_damage(iVar7,frame_dt * secondary_proj_ptr->vel_y * 700.0,3,&local_b8);
              if (pfVar13[3] <= 0.0) {
                fx_queue_add_random(pfVar13 + -1);
                fx_queue_add_random(pfVar13 + -1);
                creature_handle_death(iVar7,true);
              }
            }
          }
          pfVar13 = pfVar13 + 0x26;
          iVar7 = iVar7 + 1;
        } while ((int)pfVar13 < 0x4aa350);
      }
      else {
        local_a0 = frame_dt * *(float *)((int)(secondary_proj_ptr + -1) + 0x10);
        pfVar13 = (float *)((int)(secondary_proj_ptr + -1) + 8);
        local_9c = frame_dt * secondary_proj_ptr->vel_y;
        vec2_add(pfVar13,&local_a0);
        secondary_type = secondary_proj_ptr->type_id;
        if (secondary_type == SECONDARY_PROJECTILE_TYPE_ROCKET) {
          if (SQRT(*(float *)((int)(secondary_proj_ptr + -1) + 0x10) * *(float *)((int)(secondary_proj_ptr + -1) + 0x10) +
                   secondary_proj_ptr->vel_y * secondary_proj_ptr->vel_y) < 500.0) {
            fVar11 = 3.0;
LAB_00421c48:
            fVar11 = frame_dt * fVar11 + 1.0;
            *(float *)((int)(secondary_proj_ptr + -1) + 0x10) = fVar11 * *(float *)((int)(secondary_proj_ptr + -1) + 0x10)
            ;
            secondary_proj_ptr->vel_y = fVar11 * secondary_proj_ptr->vel_y;
          }
LAB_00421c5a:
          fVar11 = *(float *)((int)(secondary_proj_ptr + -1) + 4) - frame_dt;
LAB_00421d65:
          *(float *)((int)(secondary_proj_ptr + -1) + 4) = fVar11;
        }
        else {
          if (secondary_type == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
            if (SQRT(*(float *)((int)(secondary_proj_ptr + -1) + 0x10) * *(float *)((int)(secondary_proj_ptr + -1) + 0x10)
                     + secondary_proj_ptr->vel_y * secondary_proj_ptr->vel_y) < 600.0) {
              fVar11 = 4.0;
              goto LAB_00421c48;
            }
            goto LAB_00421c5a;
          }
          if (secondary_type == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
            if ((&creature_pool)[secondary_proj_ptr->target_id].active == '\0') {
              iVar7 = creature_find_nearest(pfVar13,-1,0.0);
              secondary_proj_ptr->target_id = iVar7;
            }
            fVar21 = (float10)fpatan((float10)*(float *)((int)(secondary_proj_ptr + -1) + 0xc) -
                                     (float10)(&creature_pool)[secondary_proj_ptr->target_id].pos_y,
                                     (float10)*pfVar13 -
                                     (float10)(&creature_pool)[secondary_proj_ptr->target_id].pos_x);
            secondary_proj_ptr[-1].vel_y = (float)(fVar21 - (float10)1.5707964);
            fVar21 = (float10)fcos((fVar21 - (float10)1.5707964) - (float10)1.5707964);
            *(float *)((int)(secondary_proj_ptr + -1) + 0x10) =
                 (float)(fVar21 * (float10)frame_dt * (float10)800.0 +
                        (float10)*(float *)((int)(secondary_proj_ptr + -1) + 0x10));
            fVar21 = (float10)fsin((float10)secondary_proj_ptr[-1].vel_y - (float10)1.5707964);
            secondary_proj_ptr->vel_y =
                 (float)(fVar21 * (float10)frame_dt * (float10)800.0 + (float10)secondary_proj_ptr->vel_y);
            if (350.0 < SQRT(*(float *)((int)(secondary_proj_ptr + -1) + 0x10) *
                             *(float *)((int)(secondary_proj_ptr + -1) + 0x10) +
                             secondary_proj_ptr->vel_y * secondary_proj_ptr->vel_y)) {
              fVar21 = (float10)fcos((float10)secondary_proj_ptr[-1].vel_y - (float10)1.5707964);
              *(float *)((int)(secondary_proj_ptr + -1) + 0x10) =
                   (float)((float10)*(float *)((int)(secondary_proj_ptr + -1) + 0x10) -
                          fVar21 * (float10)frame_dt * (float10)800.0);
              fVar21 = (float10)fsin((float10)secondary_proj_ptr[-1].vel_y - (float10)1.5707964);
              secondary_proj_ptr->vel_y =
                   (float)((float10)secondary_proj_ptr->vel_y - fVar21 * (float10)frame_dt * (float10)800.0);
            }
            fVar11 = *(float *)((int)(secondary_proj_ptr + -1) + 4) - frame_dt * 0.5;
            goto LAB_00421d65;
          }
        }
        local_c4 = secondary_proj_ptr->vel_y;
        fVar11 = secondary_proj_ptr->trail_timer -
                 (ABS(local_c4) + ABS(*(float *)((int)(secondary_proj_ptr + -1) + 0x10))) * frame_dt * 0.01;
        secondary_proj_ptr->trail_timer = fVar11;
        if (fVar11 < 0.0) {
          fVar21 = (float10)fcos((float10)secondary_proj_ptr[-1].vel_y + (float10)1.5707964);
          fStack_30 = (float)fVar21;
          local_b0 = fStack_30 * 90.0;
          local_ac = (float)(fVar21 * (float10)90.0);
          fVar21 = (float10)fcos((float10)secondary_proj_ptr[-1].vel_y - (float10)1.5707964);
          fStack_40 = (float)fVar21;
          fVar21 = (float10)fsin((float10)secondary_proj_ptr[-1].vel_y - (float10)1.5707964);
          fStack_50 = fStack_40 * 9.0;
          local_a8 = *pfVar13 - fStack_50;
          local_a4 = (float)((float10)*(float *)((int)(secondary_proj_ptr + -1) + 0xc) - fVar21 * (float10)9.0)
          ;
          iVar7 = fx_spawn_sprite(&local_a8,&local_b0,14.0);
          secondary_proj_ptr->trail_timer = 0.06;
          (&sprite_effect_pool)[iVar7].color_a = 0.25;
        }
        iVar7 = creature_find_in_radius(pfVar13,8.0,0);
        if (iVar7 != -1) {
          if ((&creature_pool)[iVar7].lifecycle_stage == 16.0) {
            _highscore_record_shots_hit = _highscore_record_shots_hit + 1;
          }
          if (bonus_freeze_timer <= 0.0) {
            iVar12 = crt_rand();
            fStack_18 = (float)(iVar12 % 0x14 + -10);
            iVar12 = crt_rand();
            local_90 = fStack_18 + (&creature_pool)[iVar7].pos_x;
            local_8c = (float)(iVar12 % 0x14 + -10) + (&creature_pool)[iVar7].pos_y;
            fx_queue_add_random(&local_90);
            iVar12 = crt_rand();
            fStack_38 = (float)(iVar12 % 0x14 + -10);
            iVar12 = crt_rand();
            local_80 = fStack_38 + (&creature_pool)[iVar7].pos_x;
            local_7c = (float)(iVar12 % 0x14 + -10) + (&creature_pool)[iVar7].pos_y;
            fx_queue_add_random(&local_80);
            iVar12 = crt_rand();
            local_28 = (float)(iVar12 % 0x14 + -10);
            iVar12 = crt_rand();
            local_70 = local_28 + (&creature_pool)[iVar7].pos_x;
            local_6c = (float)(iVar12 % 0x14 + -10) + (&creature_pool)[iVar7].pos_y;
            fx_queue_add_random(&local_70);
          }
          else {
            loop_idx = 4;
            do {
              iVar12 = crt_rand();
              effect_spawn_freeze_shard(pfVar13,(float)(iVar12 % 0x264) * 0.01);
              loop_idx = loop_idx + -1;
            } while (loop_idx != 0);
          }
          secondary_type = secondary_proj_ptr->type_id;
          local_dc = 150.0;
          if (secondary_type == SECONDARY_PROJECTILE_TYPE_ROCKET) {
            local_dc = *(float *)((int)(secondary_proj_ptr + -1) + 4) * 50.0 + 500.0;
            if (2 < _config_detail_preset) {
              effect_spawn_explosion_burst(pfVar13,0.4);
            }
          }
          else if (secondary_type == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
            local_dc = *(float *)((int)(secondary_proj_ptr + -1) + 4) * 20.0 + 80.0;
          }
          else if (secondary_type == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
            local_dc = *(float *)((int)(secondary_proj_ptr + -1) + 4) * 20.0 + 40.0;
          }
          if (((demo_mode_active == '\0') && (music_playlist_randomized_latch == '\0')) &&
             (config_game_mode != GAME_MODE_RUSH)) {
            sfx_play_exclusive(music_track_extra_0);
          }
          else {
            sfx_play_panned(sfx_explosion_medium);
          }
          local_94 = 1.0 / frame_dt;
          (&creature_pool)[iVar7].state_flag = '\x01';
          local_98 = local_94 * *(float *)((int)(secondary_proj_ptr + -1) + 0x10);
          local_94 = local_94 * secondary_proj_ptr->vel_y;
          creature_apply_damage(iVar7,local_dc,3,&local_98);
          fVar11 = bonus_freeze_timer;
          secondary_type = secondary_proj_ptr->type_id;
          if (secondary_type == SECONDARY_PROJECTILE_TYPE_ROCKET) {
            secondary_proj_ptr->type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
            *(undefined4 *)((int)(secondary_proj_ptr + -1) + 0x10) = 0;
            secondary_proj_ptr->vel_y = 1.0;
            if (fVar11 <= 0.0) {
              iVar12 = 0x14;
              do {
                iVar9 = crt_rand();
                fVar11 = (float)(iVar9 % 0x274) * 0.01;
                iVar9 = crt_rand();
                fVar21 = (float10)fcos((float10)fVar11);
                local_58 = (float)(fVar21 * (float10)(iVar9 % 0x5a));
                fVar21 = (float10)fsin((float10)fVar11);
                local_78 = local_58 + (&creature_pool)[iVar7].pos_x;
                local_74 = (float)(fVar21 * (float10)(iVar9 % 0x5a) +
                                  (float10)(&creature_pool)[iVar7].pos_y);
                fx_queue_add_random(&local_78);
                iVar12 = iVar12 + -1;
              } while (iVar12 != 0);
            }
            else {
              iVar7 = 8;
              do {
                iVar12 = crt_rand();
                effect_spawn_freeze_shard(pfVar13,(float)(iVar12 % 0x264) * 0.01);
                iVar7 = iVar7 + -1;
              } while (iVar7 != 0);
            }
          }
          else if (secondary_type == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
            secondary_proj_ptr->type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
            *(undefined4 *)((int)(secondary_proj_ptr + -1) + 0x10) = 0;
            secondary_proj_ptr->vel_y = 0.35;
            if (fVar11 <= 0.0) {
              iVar12 = 10;
              do {
                iVar9 = crt_rand();
                fVar11 = (float)(iVar9 % 0x274) * 0.01;
                uVar10 = crt_rand();
                uVar10 = uVar10 & 0x8000003f;
                if ((int)uVar10 < 0) {
                  uVar10 = (uVar10 - 1 | 0xffffffc0) + 1;
                }
                fVar21 = (float10)fcos((float10)fVar11);
                fVar20 = (float10)fsin((float10)fVar11);
                local_88 = (float)(fVar21 * (float10)(int)uVar10) + (&creature_pool)[iVar7].pos_x;
                local_84 = (float)(fVar20 * (float10)(int)uVar10 +
                                  (float10)(&creature_pool)[iVar7].pos_y);
                fx_queue_add_random(&local_88);
                iVar12 = iVar12 + -1;
              } while (iVar12 != 0);
            }
            else {
              iVar7 = 8;
              do {
                iVar12 = crt_rand();
                effect_spawn_freeze_shard(pfVar13,(float)(iVar12 % 0x264) * 0.01);
                iVar7 = iVar7 + -1;
              } while (iVar7 != 0);
            }
          }
          else if (secondary_type == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
            secondary_proj_ptr->type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
            *(undefined4 *)((int)(secondary_proj_ptr + -1) + 0x10) = 0;
            secondary_proj_ptr->vel_y = 0.25;
            if (fVar11 <= 0.0) {
              iVar12 = 3;
              do {
                iVar9 = crt_rand();
                fVar11 = (float)(iVar9 % 0x274) * 0.01;
                iVar9 = crt_rand();
                fVar21 = (float10)fcos((float10)fVar11);
                fVar20 = (float10)fsin((float10)fVar11);
                local_48 = (float)(fVar21 * (float10)(iVar9 % 0x2c)) + (&creature_pool)[iVar7].pos_x
                ;
                local_44 = (float)(fVar20 * (float10)(iVar9 % 0x2c) +
                                  (float10)(&creature_pool)[iVar7].pos_y);
                fx_queue_add_random(&local_48);
                iVar12 = iVar12 + -1;
              } while (iVar12 != 0);
            }
            else {
              iVar12 = 8;
              do {
                iVar9 = crt_rand();
                effect_spawn_freeze_shard
                          (&(&creature_pool)[iVar7].pos_x,(float)(iVar9 % 0x264) * 0.01);
                iVar12 = iVar12 + -1;
              } while (iVar12 != 0);
            }
          }
          loop_idx = 0;
          do {
            iVar7 = crt_rand();
            fVar21 = (float10)(iVar7 % 800) * (float10)0.1;
            fVar20 = (float10)fcos((float10)loop_idx * (float10)0.62831855);
            local_68 = (float)fVar20;
            fVar20 = (float10)fsin((float10)loop_idx * (float10)0.62831855);
            local_20 = (float)(fVar21 * (float10)local_68);
            local_1c = (float)(fVar20 * fVar21);
            iVar7 = fx_spawn_sprite(pfVar13,&local_20,14.0);
            loop_idx = loop_idx + 1;
            (&sprite_effect_pool)[iVar7].color_a = 0.37;
          } while (loop_idx < 10);
        }
        if (*(float *)((int)(secondary_proj_ptr + -1) + 4) <= 0.0) {
          secondary_proj_ptr->type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
          *(undefined4 *)((int)(secondary_proj_ptr + -1) + 0x10) = 0;
          secondary_proj_ptr->vel_y = 0.5;
        }
      }
    }
    secondary_proj_ptr = (secondary_projectile_vel_y_block_t *)((int)(secondary_proj_ptr + 2) + 4);
  } while ((int)secondary_proj_ptr < 0x4965f0);
  /* Sprite-effect pool housekeeping. */
  pfVar13 = &sprite_effect_pool.pos_y;
  do {
    if ((char)((sprite_effect_t *)(pfVar13 + -7))->active != '\0') {
      local_68 = frame_dt * pfVar13[1];
      fVar11 = frame_dt * pfVar13[2];
      pfVar13[-1] = local_68 + pfVar13[-1];
      *pfVar13 = fVar11 + *pfVar13;
      pfVar13[-2] = frame_dt * 3.0 + pfVar13[-2];
      fVar11 = pfVar13[-3] - frame_dt;
      pfVar13[-3] = fVar11;
      if (fVar11 <= 0.0) {
        *(undefined1 *)&((sprite_effect_t *)(pfVar13 + -7))->active = 0;
      }
      pfVar13[3] = frame_dt * 60.0 + pfVar13[3];
    }
    pfVar13 = pfVar13 + 0xb;
  } while ((int)pfVar13 < 0x49aa3c);
  /* Particle pool simulation, including sticky/freeze variants and on-contact logic. */
  slot_idx = 0;
  pfVar13 = &particle_pool.vel_y;
  do {
    if (((particle_t *)(pfVar13 + -4))->active != '\0') {
      if (SUB41(pfVar13[8],0) == '\b') {
        pfVar13[5] = pfVar13[5] - frame_dt * 0.11;
        pfVar13[7] = frame_dt * 5.0 + pfVar13[7];
        if (*(uchar *)((int)pfVar13 + -0xf) != '\0') {
          fVar11 = frame_dt * pfVar13[-1];
          if (pfVar13[5] <= 0.15) {
            fStack_40 = fVar11 * 0.55;
            fVar23 = fStack_40 * pfVar13[5];
            fVar6 = frame_dt * *pfVar13 * 0.55 * pfVar13[5];
            fStack_50 = fVar23;
            fStack_30 = fVar11;
            goto LAB_004226a3;
          }
          local_b8 = fVar11 * pfVar13[5];
          local_b4 = frame_dt * *pfVar13 * pfVar13[5];
          local_68 = fVar11;
          vec2_add(pfVar13 + -3,&local_b8);
        }
      }
      else {
        pfVar13[5] = pfVar13[5] - frame_dt * 0.9;
        pfVar13[7] = frame_dt + pfVar13[7];
        fVar11 = frame_dt * pfVar13[-1];
        if (pfVar13[5] <= 0.15) {
          local_58 = fVar11 * 2.5;
          fVar23 = local_58 * 0.15;
          fVar6 = frame_dt * *pfVar13 * 2.5 * 0.15;
          local_90 = fVar23;
          local_28 = fVar11;
LAB_004226a3:
          pfVar13[-3] = fVar23 + pfVar13[-3];
          pfVar13[-2] = fVar6 + pfVar13[-2];
        }
        else {
          fStack_38 = fVar11 * 2.5;
          local_a0 = fStack_38 * pfVar13[5];
          local_9c = frame_dt * *pfVar13 * 2.5 * pfVar13[5];
          fStack_18 = fVar11;
          vec2_add(pfVar13 + -3,&local_a0);
        }
      }
      particle_kind = SUB41(pfVar13[8],0);
      if (particle_kind == '\0') {
        if (0.0 < pfVar13[5]) {
LAB_00422767:
          if (*(uchar *)((int)pfVar13 + -0xf) == '\x01') {
            if (particle_kind == '\0') {
              iVar7 = crt_rand();
              fVar21 = (float10)(iVar7 % 100 + -0x32) * (float10)0.06 * (float10)pfVar13[5] *
                       (float10)frame_dt * (float10)1.96;
LAB_00422821:
              fVar11 = pfVar13[6];
              pfVar13[6] = (float)((float10)fVar11 - fVar21);
              fVar21 = (float10)fcos((float10)fVar11 - fVar21);
              pfVar13[-1] = (float)(fVar21 * (float10)82.0);
              fVar21 = (float10)fsin((float10)pfVar13[6]);
              fVar21 = fVar21 * (float10)82.0;
            }
            else {
              if (particle_kind != '\b') {
                iVar7 = crt_rand();
                fVar21 = (float10)(iVar7 % 100 + -0x32) * (float10)0.06 * (float10)pfVar13[5] *
                         (float10)frame_dt * (float10)1.1;
                goto LAB_00422821;
              }
              iVar7 = crt_rand();
              fVar21 = (float10)pfVar13[6] -
                       (float10)(iVar7 % 100 + -0x32) * (float10)0.06 * (float10)pfVar13[5] *
                       (float10)frame_dt * (float10)1.1;
              pfVar13[6] = (float)fVar21;
              fVar21 = (float10)fcos(fVar21);
              pfVar13[-1] = (float)(fVar21 * (float10)62.0);
              fVar21 = (float10)fsin((float10)pfVar13[6]);
              fVar21 = fVar21 * (float10)62.0;
            }
            *pfVar13 = (float)fVar21;
          }
          if (pfVar13[5] <= 1.0) {
            fVar11 = pfVar13[5];
          }
          else {
            fVar11 = 1.0;
          }
          pfVar13[4] = fVar11;
          fVar11 = 1.0 - pfVar13[5] * 0.95;
          pfVar13[1] = fVar11;
          pfVar13[2] = fVar11;
          if (*(uchar *)((int)pfVar13 + -0xf) != '\0') {
            pfVar1 = pfVar13 + -3;
            fVar11 = (float)creature_find_in_radius(pfVar1,pfVar13[5] * 8.0,0);
            if (fVar11 != -NAN) {
              *(uchar *)((int)pfVar13 + -0xf) = '\0';
              if (SUB41(pfVar13[8],0) == '\b') {
                fVar23 = (&creature_pool)[(int)fVar11].pos_y;
                *pfVar1 = (&creature_pool)[(int)fVar11].pos_x;
                pfVar13[-2] = fVar23;
                pfVar13[-1] = 0.0;
                *pfVar13 = 0.0;
                (&creature_pool)[(int)fVar11].state_flag = '\0';
                pfVar13[9] = fVar11;
              }
              else {
                fVar23 = pfVar13[6];
                while (6.2831855 < fVar23) {
                  fVar23 = pfVar13[6] - 6.2831855;
                  pfVar13[6] = fVar23;
                }
                fVar23 = pfVar13[6];
                while (fVar23 < 0.0) {
                  fVar23 = pfVar13[6] + 6.2831855;
                  pfVar13[6] = fVar23;
                }
                local_80 = (float)((float10)frame_dt * (float10)pfVar13[-1]);
                local_70 = *pfVar1 - local_80;
                pfVar1 = &(&creature_pool)[(int)fVar11].pos_x;
                local_98 = local_70 - *pfVar1;
                fVar21 = (float10)fpatan(((float10)pfVar13[-2] -
                                         (float10)frame_dt * (float10)*pfVar13) -
                                         (float10)(&creature_pool)[(int)fVar11].pos_y,
                                         (float10)local_98);
                if ((float10)6.2831855 < fVar21) {
                  do {
                    fVar21 = fVar21 - (float10)6.2831855;
                  } while ((float10)6.2831855 < fVar21);
                }
                if (fVar21 < (float10)0.0) {
                  do {
                    fVar21 = fVar21 + (float10)6.2831855;
                  } while (fVar21 < (float10)0.0);
                }
                if ((float10)pfVar13[6] <= fVar21) {
                  fVar23 = pfVar13[6] + 1.2566371;
                }
                else {
                  fVar23 = pfVar13[6] - 1.2566371;
                }
                pfVar13[6] = fVar23;
                fVar21 = (float10)fcos((float10)pfVar13[6]);
                pfVar13[-1] = (float)(fVar21 * (float10)82.0);
                fVar21 = (float10)fsin((float10)pfVar13[6]);
                *pfVar13 = (float)(fVar21 * (float10)82.0);
                iVar7 = crt_rand();
                (&creature_pool)[(int)fVar11].state_flag = '\x01';
                local_b0 = 0.0;
                local_ac = 0.0;
                fVar23 = (float)(iVar7 % 10) * 0.1;
                pfVar13[-1] = fVar23 * pfVar13[-1];
                *pfVar13 = fVar23 * *pfVar13;
                creature_apply_damage((int)fVar11,pfVar13[5] * 10.0,4,&local_b0);
                if (1.6 < (&creature_pool)[(int)fVar11].tint_g +
                          (&creature_pool)[(int)fVar11].tint_b +
                          (&creature_pool)[(int)fVar11].tint_r) {
                  fVar23 = 1.0 - pfVar13[5] * 0.01;
                  (&creature_pool)[(int)fVar11].tint_r =
                       fVar23 * (&creature_pool)[(int)fVar11].tint_r;
                  (&creature_pool)[(int)fVar11].tint_g =
                       fVar23 * (&creature_pool)[(int)fVar11].tint_g;
                  (&creature_pool)[(int)fVar11].tint_b =
                       fVar23 * (&creature_pool)[(int)fVar11].tint_b;
                  if (0.0 <= (&creature_pool)[(int)fVar11].tint_r) {
                    if (1.0 < (&creature_pool)[(int)fVar11].tint_r) {
                      (&creature_pool)[(int)fVar11].tint_r = 1.0;
                    }
                  }
                  else {
                    (&creature_pool)[(int)fVar11].tint_r = 0.0;
                  }
                  if (0.0 <= (&creature_pool)[(int)fVar11].tint_g) {
                    if (1.0 < (&creature_pool)[(int)fVar11].tint_g) {
                      (&creature_pool)[(int)fVar11].tint_g = 1.0;
                    }
                  }
                  else {
                    (&creature_pool)[(int)fVar11].tint_g = 0.0;
                  }
                  if (0.0 <= (&creature_pool)[(int)fVar11].tint_b) {
                    if (1.0 < (&creature_pool)[(int)fVar11].tint_b) {
                      (&creature_pool)[(int)fVar11].tint_b = 1.0;
                    }
                  }
                  else {
                    (&creature_pool)[(int)fVar11].tint_b = 0.0;
                  }
                  if (0.0 <= (&creature_pool)[(int)fVar11].tint_a) {
                    if (1.0 < (&creature_pool)[(int)fVar11].tint_a) {
                      (&creature_pool)[(int)fVar11].tint_a = 1.0;
                    }
                  }
                  else {
                    (&creature_pool)[(int)fVar11].tint_a = 0.0;
                  }
                }
                if (slot_idx % 3 == 0) {
                  iVar7 = crt_rand();
                  iVar12 = crt_rand();
                  local_a4 = (float)(iVar12 % 0x3c + -0x1e);
                  local_a8 = (float)(iVar7 % 0x3c + -0x1e);
                  iVar7 = fx_spawn_sprite(pfVar1,&local_a8,13.0);
                  (&sprite_effect_pool)[iVar7].color_a = 0.7;
                }
                fx_queue_add_random(pfVar1);
                local_74 = *pfVar13;
                local_84 = local_74 * frame_dt;
                *pfVar1 = pfVar13[-1] * frame_dt + *pfVar1;
                (&creature_pool)[(int)fVar11].pos_y = local_84 + (&creature_pool)[(int)fVar11].pos_y
                ;
              }
            }
          }
        }
        else {
          ((particle_t *)(pfVar13 + -4))->active = '\0';
        }
      }
      else {
        if (0.8 < pfVar13[5]) goto LAB_00422767;
        ((particle_t *)(pfVar13 + -4))->active = '\0';
        if ((SUB41(pfVar13[8],0) == '\b') && (pfVar13[9] != -NAN)) {
          if ((&creature_pool)[(int)pfVar13[9]].active != '\0') {
            iVar7 = crt_rand();
            sfx_play_panned((float)creature_type_table[(&creature_pool)[(int)pfVar13[9]].type_id].
                                   sfx_bank_a[iVar7 % 3]);
          }
          creature_handle_death((int)pfVar13[9],false);
        }
      }
    }
    pfVar13 = pfVar13 + 0xe;
    slot_idx = slot_idx + 1;
    if (0x495ac7 < (int)pfVar13) {
      return;
    }
  } while( true );
}
