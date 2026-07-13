/* WORK COPY: creature_spawn_template */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* creature_spawn_template @ 00430af0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns creature(s) from template id; heading -100 uses a random heading */

void * creature_spawn_template(int template_id, float *pos, float heading)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float *origin_pos_ptr;
  int root_slot_idx;
  int iVar7;
  int random_heading_roll;
  int ring_member_idx;
  int child_slot_idx;
  uint rng_value;
  creature_t *creature_ptr;
  float10 fVar11;
  float10 fVar12;
  int local_48;
  float local_4;
  
  /* Shared root-slot init used by every template branch below. */
  origin_pos_ptr = pos;
  root_slot_idx = creature_alloc_slot();
  if (heading == -100.0) {
    random_heading_roll = crt_rand();
    heading = (float)(random_heading_roll % 0x274) * 0.01;
  }
  creature_ptr = &creature_pool + root_slot_idx;
  (&creature_pool)[root_slot_idx].ai_mode = 0;
  (&creature_pool)[root_slot_idx].pos_x = *pos;
  fVar4 = pos[1];
  (&creature_pool)[root_slot_idx].vel_x = 0.0;
  (&creature_pool)[root_slot_idx].pos_y = fVar4;
  (&creature_pool)[root_slot_idx].collision_flag = '\0';
  (&creature_pool)[root_slot_idx].collision_timer = 0.0;
  creature_ptr->active = '\x01';
  *(undefined1 *)&(&creature_pool)[root_slot_idx].force_target = 0;
  (&creature_pool)[root_slot_idx].state_flag = '\x01';
  (&creature_pool)[root_slot_idx].lifecycle_stage = 16.0;
  (&creature_pool)[root_slot_idx].vel_y = 0.0;
  random_heading_roll = crt_rand();
  (&creature_pool)[root_slot_idx].attack_cooldown = 0.0;
  (&creature_pool)[root_slot_idx].heading = (float)(random_heading_roll % 0x13a) * 0.01;
  /* Multi-body template: root + 8 linked satellites in a full ring. */
  if (template_id == 0x12) {
    (&creature_pool)[root_slot_idx].tint_r = 0.65;
    (&creature_pool)[root_slot_idx].type_id = 2;
    (&creature_pool)[root_slot_idx].tint_g = 0.85;
    (&creature_pool)[root_slot_idx].health = 200.0;
    (&creature_pool)[root_slot_idx].move_speed = 2.2;
    (&creature_pool)[root_slot_idx].tint_b = 0.97;
    (&creature_pool)[root_slot_idx].reward_value = 600.0;
    (&creature_pool)[root_slot_idx].size = 55.0;
    (&creature_pool)[root_slot_idx].tint_a = 1.0;
    (&creature_pool)[root_slot_idx].contact_damage = 14.0;
    (&creature_pool)[root_slot_idx].max_health = 200.0;
    ring_member_idx = 0;
    do {
      iVar7 = creature_alloc_slot();
      fVar11 = (float10)fcos((float10)ring_member_idx * (float10)0.7853982);
      creature_ptr = &creature_pool + iVar7;
      (&creature_pool)[iVar7].ai_mode = 3;
      (&creature_pool)[iVar7].link_index = root_slot_idx;
      (&creature_pool)[iVar7].target_offset_x = (float)(fVar11 * (float10)100.0);
      fVar11 = (float10)fsin((float10)ring_member_idx * (float10)0.7853982);
      (&creature_pool)[iVar7].target_offset_y = (float)(fVar11 * (float10)100.0);
      (&creature_pool)[iVar7].pos_x = *origin_pos_ptr;
      (&creature_pool)[iVar7].pos_y = origin_pos_ptr[1];
      (&creature_pool)[iVar7].vel_x = 0.0;
      (&creature_pool)[iVar7].vel_y = 0.0;
      (&creature_pool)[iVar7].collision_flag = '\0';
      (&creature_pool)[iVar7].tint_r = 0.32000002;
      (&creature_pool)[iVar7].health = 40.0;
      (&creature_pool)[iVar7].max_health = 40.0;
      (&creature_pool)[iVar7].tint_g = 0.58800006;
      ring_member_idx = ring_member_idx + 1;
      (&creature_pool)[iVar7].tint_b = 0.426;
      (&creature_pool)[iVar7].collision_timer = 0.0;
      creature_ptr->active = '\x01';
      (&creature_pool)[iVar7].state_flag = '\x01';
      (&creature_pool)[iVar7].lifecycle_stage = 16.0;
      (&creature_pool)[iVar7].attack_cooldown = 0.0;
      (&creature_pool)[iVar7].type_id = 2;
      (&creature_pool)[iVar7].move_speed = 2.4;
      (&creature_pool)[iVar7].reward_value = 60.0;
      (&creature_pool)[iVar7].tint_a = 1.0;
      (&creature_pool)[iVar7].size = 50.0;
      (&creature_pool)[iVar7].contact_damage = 4.0;
    } while (ring_member_idx < 8);
  }
  else if (template_id == 0x19) {
    /* Multi-body template: root + 5 linked escorts in a pentagon ring. */
    (&creature_pool)[root_slot_idx].tint_r = 0.95;
    (&creature_pool)[root_slot_idx].type_id = 2;
    (&creature_pool)[root_slot_idx].tint_g = 0.55;
    (&creature_pool)[root_slot_idx].health = 50.0;
    (&creature_pool)[root_slot_idx].move_speed = 3.8;
    (&creature_pool)[root_slot_idx].tint_b = 0.37;
    (&creature_pool)[root_slot_idx].reward_value = 300.0;
    (&creature_pool)[root_slot_idx].size = 55.0;
    (&creature_pool)[root_slot_idx].tint_a = 1.0;
    (&creature_pool)[root_slot_idx].contact_damage = 40.0;
    (&creature_pool)[root_slot_idx].max_health = 50.0;
    ring_member_idx = 0;
    do {
      iVar7 = creature_alloc_slot();
      fVar11 = (float10)fcos((float10)ring_member_idx * (float10)1.2566371);
      creature_ptr = &creature_pool + iVar7;
      (&creature_pool)[iVar7].ai_mode = 5;
      (&creature_pool)[iVar7].link_index = root_slot_idx;
      (&creature_pool)[iVar7].target_offset_x = (float)(fVar11 * (float10)110.0);
      fVar11 = (float10)fsin((float10)ring_member_idx * (float10)1.2566371);
      (&creature_pool)[iVar7].target_offset_y = (float)(fVar11 * (float10)110.0);
      fVar4 = (&creature_pool)[iVar7].target_offset_x;
      fVar1 = *origin_pos_ptr;
      fVar2 = (&creature_pool)[iVar7].target_offset_y;
      fVar3 = origin_pos_ptr[1];
      (&creature_pool)[iVar7].vel_x = 0.0;
      (&creature_pool)[iVar7].pos_x = fVar4 + fVar1;
      (&creature_pool)[iVar7].vel_y = 0.0;
      (&creature_pool)[iVar7].pos_y = fVar2 + fVar3;
      (&creature_pool)[iVar7].health = 220.0;
      (&creature_pool)[iVar7].max_health = 220.0;
      (&creature_pool)[iVar7].tint_r = 0.7125;
      ring_member_idx = ring_member_idx + 1;
      (&creature_pool)[iVar7].tint_g = 0.41250002;
      (&creature_pool)[iVar7].collision_flag = '\0';
      (&creature_pool)[iVar7].tint_b = 0.2775;
      (&creature_pool)[iVar7].collision_timer = 0.0;
      creature_ptr->active = '\x01';
      (&creature_pool)[iVar7].state_flag = '\x01';
      (&creature_pool)[iVar7].lifecycle_stage = 16.0;
      (&creature_pool)[iVar7].attack_cooldown = 0.0;
      (&creature_pool)[iVar7].type_id = 2;
      (&creature_pool)[iVar7].move_speed = 3.8;
      (&creature_pool)[iVar7].reward_value = 60.0;
      (&creature_pool)[iVar7].tint_a = 0.6;
      (&creature_pool)[iVar7].size = 50.0;
      (&creature_pool)[iVar7].contact_damage = 35.0;
    } while (ring_member_idx < 5);
  }
  else {
    /* Hand-authored boss/layout templates and the large generic-id dispatch ladder. */
    if (template_id == 0x11) {
      (&creature_pool)[root_slot_idx].type_id = 1;
      (&creature_pool)[root_slot_idx].pos_x = *pos;
      (&creature_pool)[root_slot_idx].pos_y = pos[1];
      (&creature_pool)[root_slot_idx].ai_mode = 1;
      (&creature_pool)[root_slot_idx].tint_r = 0.99;
      (&creature_pool)[root_slot_idx].tint_g = 0.99;
      (&creature_pool)[root_slot_idx].health = 1500.0;
      (&creature_pool)[root_slot_idx].move_speed = 2.1;
      (&creature_pool)[root_slot_idx].tint_b = 0.21;
      (&creature_pool)[root_slot_idx].reward_value = 1000.0;
      (&creature_pool)[root_slot_idx].size = 69.0;
      (&creature_pool)[root_slot_idx].tint_a = 1.0;
      (&creature_pool)[root_slot_idx].contact_damage = 150.0;
      (&creature_pool)[root_slot_idx].max_health = 1500.0;
      local_48 = 2;
      pos = (float *)0xffffff00;
      iVar7 = root_slot_idx;
      do {
        child_slot_idx = creature_alloc_slot();
        (&creature_pool)[child_slot_idx].target_offset_x = (float)(int)pos;
        creature_ptr = &creature_pool + child_slot_idx;
        (&creature_pool)[child_slot_idx].ai_mode = 3;
        (&creature_pool)[child_slot_idx].link_index = iVar7;
        (&creature_pool)[child_slot_idx].target_offset_y = -256.0;
        fVar11 = (float10)fcos((float10)local_48 * (float10)0.3926991);
        fVar12 = (float10)fsin((float10)local_48 * (float10)0.3926991);
        fVar4 = origin_pos_ptr[1];
        (&creature_pool)[child_slot_idx].pos_x = (float)fVar11 * 256.0 + *origin_pos_ptr;
        (&creature_pool)[child_slot_idx].vel_x = 0.0;
        (&creature_pool)[child_slot_idx].tint_r = 0.6;
        (&creature_pool)[child_slot_idx].pos_y = (float)(fVar12 * (float10)256.0 + (float10)fVar4);
        (&creature_pool)[child_slot_idx].tint_g = 0.6;
        (&creature_pool)[child_slot_idx].vel_y = 0.0;
        (&creature_pool)[child_slot_idx].tint_b = 0.31;
        (&creature_pool)[child_slot_idx].health = 60.0;
        (&creature_pool)[child_slot_idx].reward_value = 60.0;
        (&creature_pool)[child_slot_idx].max_health = 60.0;
        (&creature_pool)[child_slot_idx].tint_a = 1.0;
        pos = pos + 0x10;
        local_48 = local_48 + 2;
        (&creature_pool)[child_slot_idx].collision_flag = '\0';
        (&creature_pool)[child_slot_idx].collision_timer = 0.0;
        creature_ptr->active = '\x01';
        (&creature_pool)[child_slot_idx].state_flag = '\x01';
        (&creature_pool)[child_slot_idx].lifecycle_stage = 16.0;
        (&creature_pool)[child_slot_idx].attack_cooldown = 0.0;
        (&creature_pool)[child_slot_idx].type_id = 1;
        (&creature_pool)[child_slot_idx].move_speed = 2.4;
        (&creature_pool)[child_slot_idx].size = 50.0;
        (&creature_pool)[child_slot_idx].contact_damage = 14.0;
        iVar7 = child_slot_idx;
      } while ((int)pos < 0);
    }
    else {
      if (template_id != 0x13) {
        /* Grid/ring variants and spawner-controller archetypes. */
        if (template_id == 0x14) {
          (&creature_pool)[root_slot_idx].type_id = 2;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].ai_mode = 2;
          (&creature_pool)[root_slot_idx].tint_r = 0.7;
          (&creature_pool)[root_slot_idx].tint_g = 0.8;
          (&creature_pool)[root_slot_idx].health = 1500.0;
          (&creature_pool)[root_slot_idx].move_speed = 2.0;
          (&creature_pool)[root_slot_idx].tint_b = 0.31;
          (&creature_pool)[root_slot_idx].reward_value = 600.0;
          (&creature_pool)[root_slot_idx].size = 50.0;
          (&creature_pool)[root_slot_idx].tint_a = 1.0;
          (&creature_pool)[root_slot_idx].contact_damage = 40.0;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].max_health = 1500.0;
          local_48 = 0;
          do {
            pos = (float *)0x80;
            do {
              iVar7 = creature_alloc_slot();
              (&creature_pool)[iVar7].target_offset_y = (float)(int)pos;
              creature_ptr = &creature_pool + iVar7;
              (&creature_pool)[iVar7].ai_mode = 5;
              (&creature_pool)[iVar7].heading = 0.0;
              (&creature_pool)[iVar7].anim_phase = 0.0;
              (&creature_pool)[iVar7].link_index = root_slot_idx;
              (&creature_pool)[iVar7].target_offset_x = (float)local_48;
              fVar4 = *origin_pos_ptr;
              fVar1 = (&creature_pool)[iVar7].target_offset_x;
              fVar2 = (&creature_pool)[iVar7].target_offset_y;
              fVar3 = origin_pos_ptr[1];
              (&creature_pool)[iVar7].vel_x = 0.0;
              (&creature_pool)[iVar7].pos_x = fVar4 + fVar1;
              (&creature_pool)[iVar7].vel_y = 0.0;
              (&creature_pool)[iVar7].pos_y = fVar2 + fVar3;
              (&creature_pool)[iVar7].tint_r = 0.4;
              (&creature_pool)[iVar7].health = 40.0;
              (&creature_pool)[iVar7].max_health = 40.0;
              (&creature_pool)[iVar7].tint_g = 0.7;
              pos = pos + 0x10;
              (&creature_pool)[iVar7].tint_b = 0.11;
              (&creature_pool)[iVar7].collision_flag = '\0';
              (&creature_pool)[iVar7].collision_timer = 0.0;
              creature_ptr->active = '\x01';
              (&creature_pool)[iVar7].state_flag = '\x01';
              (&creature_pool)[iVar7].lifecycle_stage = 16.0;
              (&creature_pool)[iVar7].attack_cooldown = 0.0;
              (&creature_pool)[iVar7].type_id = 2;
              (&creature_pool)[iVar7].move_speed = 2.0;
              (&creature_pool)[iVar7].reward_value = 60.0;
              (&creature_pool)[iVar7].tint_a = 1.0;
              (&creature_pool)[iVar7].size = 50.0;
              (&creature_pool)[iVar7].contact_damage = 4.0;
            } while ((int)pos < 0x101);
            local_48 = local_48 + -0x40;
          } while (-0x240 < local_48);
        }
        else if (template_id == 0x15) {
          (&creature_pool)[root_slot_idx].type_id = 2;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].ai_mode = 2;
          (&creature_pool)[root_slot_idx].tint_r = 1.0;
          (&creature_pool)[root_slot_idx].tint_g = 1.0;
          (&creature_pool)[root_slot_idx].health = 1500.0;
          (&creature_pool)[root_slot_idx].move_speed = 2.0;
          (&creature_pool)[root_slot_idx].tint_b = 1.0;
          (&creature_pool)[root_slot_idx].reward_value = 600.0;
          (&creature_pool)[root_slot_idx].size = 60.0;
          (&creature_pool)[root_slot_idx].tint_a = 1.0;
          (&creature_pool)[root_slot_idx].contact_damage = 40.0;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].max_health = 1500.0;
          local_48 = 0;
          do {
            pos = (float *)0x80;
            do {
              iVar7 = creature_alloc_slot();
              (&creature_pool)[iVar7].target_offset_y = (float)(int)pos;
              creature_ptr = &creature_pool + iVar7;
              (&creature_pool)[iVar7].ai_mode = 4;
              (&creature_pool)[iVar7].heading = 0.0;
              (&creature_pool)[iVar7].anim_phase = 0.0;
              (&creature_pool)[iVar7].link_index = root_slot_idx;
              (&creature_pool)[iVar7].target_offset_x = (float)local_48;
              fVar4 = *origin_pos_ptr;
              fVar1 = (&creature_pool)[iVar7].target_offset_x;
              fVar2 = (&creature_pool)[iVar7].target_offset_y;
              fVar3 = origin_pos_ptr[1];
              (&creature_pool)[iVar7].vel_x = 0.0;
              (&creature_pool)[iVar7].pos_x = fVar4 + fVar1;
              (&creature_pool)[iVar7].vel_y = 0.0;
              (&creature_pool)[iVar7].pos_y = fVar2 + fVar3;
              (&creature_pool)[iVar7].health = 40.0;
              (&creature_pool)[iVar7].max_health = 40.0;
              (&creature_pool)[iVar7].tint_r = 0.4;
              pos = pos + 0x10;
              (&creature_pool)[iVar7].tint_g = 0.7;
              (&creature_pool)[iVar7].collision_flag = '\0';
              (&creature_pool)[iVar7].tint_b = 0.11;
              (&creature_pool)[iVar7].collision_timer = 0.0;
              creature_ptr->active = '\x01';
              (&creature_pool)[iVar7].state_flag = '\x01';
              (&creature_pool)[iVar7].lifecycle_stage = 16.0;
              (&creature_pool)[iVar7].attack_cooldown = 0.0;
              (&creature_pool)[iVar7].type_id = 2;
              (&creature_pool)[iVar7].move_speed = 2.0;
              (&creature_pool)[iVar7].reward_value = 60.0;
              (&creature_pool)[iVar7].tint_a = 1.0;
              (&creature_pool)[iVar7].size = 50.0;
              (&creature_pool)[iVar7].contact_damage = 4.0;
            } while ((int)pos < 0x101);
            local_48 = local_48 + -0x40;
          } while (-0x240 < local_48);
        }
        else if (template_id == 0x17) {
          (&creature_pool)[root_slot_idx].type_id = 3;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].tint_r = 1.0;
          (&creature_pool)[root_slot_idx].tint_g = 1.0;
          (&creature_pool)[root_slot_idx].ai_mode = 2;
          (&creature_pool)[root_slot_idx].health = 1500.0;
          (&creature_pool)[root_slot_idx].tint_b = 1.0;
          (&creature_pool)[root_slot_idx].move_speed = 2.0;
          (&creature_pool)[root_slot_idx].reward_value = 600.0;
          (&creature_pool)[root_slot_idx].tint_a = 1.0;
          (&creature_pool)[root_slot_idx].size = 60.0;
          (&creature_pool)[root_slot_idx].contact_damage = 40.0;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].max_health = 1500.0;
          local_48 = 0;
          do {
            pos = (float *)0x80;
            do {
              iVar7 = creature_alloc_slot();
              (&creature_pool)[iVar7].target_offset_y = (float)(int)pos;
              creature_ptr = &creature_pool + iVar7;
              (&creature_pool)[iVar7].ai_mode = 4;
              (&creature_pool)[iVar7].heading = 0.0;
              (&creature_pool)[iVar7].anim_phase = 0.0;
              (&creature_pool)[iVar7].link_index = root_slot_idx;
              (&creature_pool)[iVar7].target_offset_x = (float)local_48;
              fVar4 = (&creature_pool)[iVar7].target_offset_x;
              fVar1 = *origin_pos_ptr;
              fVar2 = (&creature_pool)[iVar7].target_offset_y;
              fVar3 = origin_pos_ptr[1];
              (&creature_pool)[iVar7].vel_x = 0.0;
              (&creature_pool)[iVar7].pos_x = fVar4 + fVar1;
              (&creature_pool)[iVar7].vel_y = 0.0;
              (&creature_pool)[iVar7].pos_y = fVar2 + fVar3;
              (&creature_pool)[iVar7].health = 40.0;
              (&creature_pool)[iVar7].max_health = 40.0;
              (&creature_pool)[iVar7].tint_r = 0.4;
              pos = pos + 0x10;
              (&creature_pool)[iVar7].tint_g = 0.7;
              (&creature_pool)[iVar7].collision_flag = '\0';
              (&creature_pool)[iVar7].tint_b = 0.11;
              (&creature_pool)[iVar7].collision_timer = 0.0;
              creature_ptr->active = '\x01';
              (&creature_pool)[iVar7].state_flag = '\x01';
              (&creature_pool)[iVar7].lifecycle_stage = 16.0;
              (&creature_pool)[iVar7].attack_cooldown = 0.0;
              (&creature_pool)[iVar7].type_id = 3;
              (&creature_pool)[iVar7].move_speed = 2.0;
              (&creature_pool)[iVar7].reward_value = 60.0;
              (&creature_pool)[iVar7].tint_a = 1.0;
              (&creature_pool)[iVar7].size = 50.0;
              (&creature_pool)[iVar7].contact_damage = 4.0;
            } while ((int)pos < 0x101);
            local_48 = local_48 + -0x40;
          } while (-0x240 < local_48);
        }
        else if (template_id == 0x16) {
          (&creature_pool)[root_slot_idx].type_id = 1;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].tint_r = 1.0;
          (&creature_pool)[root_slot_idx].tint_g = 1.0;
          (&creature_pool)[root_slot_idx].ai_mode = 2;
          (&creature_pool)[root_slot_idx].health = 1500.0;
          (&creature_pool)[root_slot_idx].tint_b = 1.0;
          (&creature_pool)[root_slot_idx].move_speed = 2.0;
          (&creature_pool)[root_slot_idx].reward_value = 600.0;
          (&creature_pool)[root_slot_idx].tint_a = 1.0;
          (&creature_pool)[root_slot_idx].size = 64.0;
          (&creature_pool)[root_slot_idx].contact_damage = 40.0;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].max_health = 1500.0;
          local_48 = 0;
          do {
            pos = (float *)0x80;
            do {
              iVar7 = creature_alloc_slot();
              (&creature_pool)[iVar7].target_offset_y = (float)(int)pos;
              creature_ptr = &creature_pool + iVar7;
              (&creature_pool)[iVar7].ai_mode = 4;
              (&creature_pool)[iVar7].heading = 0.0;
              (&creature_pool)[iVar7].anim_phase = 0.0;
              (&creature_pool)[iVar7].link_index = root_slot_idx;
              (&creature_pool)[iVar7].target_offset_x = (float)local_48;
              fVar4 = (&creature_pool)[iVar7].target_offset_x;
              fVar1 = *origin_pos_ptr;
              fVar2 = (&creature_pool)[iVar7].target_offset_y;
              fVar3 = origin_pos_ptr[1];
              (&creature_pool)[iVar7].vel_x = 0.0;
              (&creature_pool)[iVar7].pos_x = fVar4 + fVar1;
              (&creature_pool)[iVar7].vel_y = 0.0;
              (&creature_pool)[iVar7].pos_y = fVar2 + fVar3;
              (&creature_pool)[iVar7].health = 40.0;
              (&creature_pool)[iVar7].max_health = 40.0;
              (&creature_pool)[iVar7].tint_r = 0.4;
              pos = pos + 0x10;
              (&creature_pool)[iVar7].tint_g = 0.7;
              (&creature_pool)[iVar7].collision_flag = '\0';
              (&creature_pool)[iVar7].tint_b = 0.11;
              (&creature_pool)[iVar7].collision_timer = 0.0;
              creature_ptr->active = '\x01';
              (&creature_pool)[iVar7].state_flag = '\x01';
              (&creature_pool)[iVar7].lifecycle_stage = 16.0;
              (&creature_pool)[iVar7].attack_cooldown = 0.0;
              (&creature_pool)[iVar7].type_id = 1;
              (&creature_pool)[iVar7].move_speed = 2.0;
              (&creature_pool)[iVar7].reward_value = 60.0;
              (&creature_pool)[iVar7].tint_a = 1.0;
              (&creature_pool)[iVar7].size = 60.0;
              (&creature_pool)[iVar7].contact_damage = 4.0;
            } while ((int)pos < 0x101);
            local_48 = local_48 + -0x40;
          } while (-0x240 < local_48);
        }
        else {
          if (template_id != 0xf) {
            if (template_id == 0x18) {
              (&creature_pool)[root_slot_idx].type_id = 2;
              (&creature_pool)[root_slot_idx].pos_x = *pos;
              fVar4 = pos[1];
              (&creature_pool)[root_slot_idx].ai_mode = 2;
              (&creature_pool)[root_slot_idx].tint_r = 0.7;
              (&creature_pool)[root_slot_idx].pos_y = fVar4;
              (&creature_pool)[root_slot_idx].tint_g = 0.8;
              (&creature_pool)[root_slot_idx].health = 500.0;
              (&creature_pool)[root_slot_idx].move_speed = 2.0;
              (&creature_pool)[root_slot_idx].tint_b = 0.31;
              (&creature_pool)[root_slot_idx].reward_value = 600.0;
              (&creature_pool)[root_slot_idx].tint_a = 1.0;
              (&creature_pool)[root_slot_idx].size = 40.0;
              (&creature_pool)[root_slot_idx].contact_damage = 40.0;
              (&creature_pool)[root_slot_idx].pos_x = *pos;
              (&creature_pool)[root_slot_idx].pos_y = pos[1];
              (&creature_pool)[root_slot_idx].max_health = 500.0;
              local_48 = 0;
              do {
                pos = (float *)0x80;
                do {
                  iVar7 = creature_alloc_slot();
                  (&creature_pool)[iVar7].target_offset_y = (float)(int)pos;
                  creature_ptr = &creature_pool + iVar7;
                  (&creature_pool)[iVar7].ai_mode = 3;
                  (&creature_pool)[iVar7].heading = 0.0;
                  (&creature_pool)[iVar7].anim_phase = 0.0;
                  (&creature_pool)[iVar7].link_index = root_slot_idx;
                  (&creature_pool)[iVar7].target_offset_x = (float)local_48;
                  fVar4 = (&creature_pool)[iVar7].target_offset_x;
                  fVar1 = *origin_pos_ptr;
                  fVar2 = (&creature_pool)[iVar7].target_offset_y;
                  fVar3 = origin_pos_ptr[1];
                  (&creature_pool)[iVar7].vel_x = 0.0;
                  (&creature_pool)[iVar7].pos_x = fVar4 + fVar1;
                  (&creature_pool)[iVar7].vel_y = 0.0;
                  (&creature_pool)[iVar7].pos_y = fVar2 + fVar3;
                  (&creature_pool)[iVar7].health = 260.0;
                  (&creature_pool)[iVar7].max_health = 260.0;
                  (&creature_pool)[iVar7].tint_r = 0.7125;
                  pos = pos + 0x10;
                  (&creature_pool)[iVar7].tint_g = 0.41250002;
                  (&creature_pool)[iVar7].collision_flag = '\0';
                  (&creature_pool)[iVar7].tint_b = 0.2775;
                  (&creature_pool)[iVar7].collision_timer = 0.0;
                  creature_ptr->active = '\x01';
                  (&creature_pool)[iVar7].state_flag = '\x01';
                  (&creature_pool)[iVar7].lifecycle_stage = 16.0;
                  (&creature_pool)[iVar7].attack_cooldown = 0.0;
                  (&creature_pool)[iVar7].type_id = 2;
                  (&creature_pool)[iVar7].move_speed = 3.8;
                  (&creature_pool)[iVar7].reward_value = 60.0;
                  (&creature_pool)[iVar7].tint_a = 0.6;
                  (&creature_pool)[iVar7].size = 50.0;
                  (&creature_pool)[iVar7].contact_damage = 35.0;
                } while ((int)pos < 0x101);
                local_48 = local_48 + -0x40;
              } while (-0x240 < local_48);
              goto LAB_004310b8;
            }
            if (template_id == 1) {
              /* Boss-class single entities and spawner-controller roots. */
              (&creature_pool)[root_slot_idx].type_id = 4;
              (&creature_pool)[root_slot_idx].flags = 8;
              (&creature_pool)[root_slot_idx].size = 80.0;
              (&creature_pool)[root_slot_idx].health = 400.0;
              (&creature_pool)[root_slot_idx].move_speed = 2.0;
              (&creature_pool)[root_slot_idx].reward_value = 1000.0;
              (&creature_pool)[root_slot_idx].tint_a = 1.0;
              (&creature_pool)[root_slot_idx].tint_r = 0.8;
              (&creature_pool)[root_slot_idx].tint_g = 0.7;
              (&creature_pool)[root_slot_idx].tint_b = 0.4;
              (&creature_pool)[root_slot_idx].contact_damage = 17.0;
              goto LAB_004310b8;
            }
            if (template_id == 10) {
              (&creature_pool)[root_slot_idx].type_id = 2;
              (&creature_pool)[root_slot_idx].flags = 4;
              iVar7 = creature_spawn_slot_alloc();
              (&creature_pool)[root_slot_idx].link_index = iVar7;
              (&creature_spawn_slot_table)[iVar7].timer_s = 2.0;
              (&creature_spawn_slot_table)[iVar7].count = 0;
              (&creature_spawn_slot_table)[iVar7].limit = 100;
              (&creature_spawn_slot_table)[iVar7].interval_s = 5.0;
              (&creature_spawn_slot_table)[iVar7].template_id = 0x32;
              (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
              (&creature_pool)[root_slot_idx].size = 55.0;
              (&creature_pool)[root_slot_idx].health = 1000.0;
              (&creature_pool)[root_slot_idx].move_speed = 1.5;
              (&creature_pool)[root_slot_idx].reward_value = 3000.0;
              (&creature_pool)[root_slot_idx].tint_a = 1.0;
              (&creature_pool)[root_slot_idx].tint_r = 0.8;
              (&creature_pool)[root_slot_idx].tint_g = 0.7;
              (&creature_pool)[root_slot_idx].tint_b = 0.4;
              (&creature_pool)[root_slot_idx].contact_damage = 0.0;
              goto LAB_004310b8;
            }
            if (template_id == 0xb) {
              (&creature_pool)[root_slot_idx].type_id = 2;
              (&creature_pool)[root_slot_idx].flags = 4;
              iVar7 = creature_spawn_slot_alloc();
              (&creature_pool)[root_slot_idx].link_index = iVar7;
              (&creature_spawn_slot_table)[iVar7].timer_s = 2.0;
              (&creature_spawn_slot_table)[iVar7].count = 0;
              (&creature_spawn_slot_table)[iVar7].limit = 100;
              (&creature_spawn_slot_table)[iVar7].interval_s = 6.0;
              (&creature_spawn_slot_table)[iVar7].template_id = 0x3c;
              (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
              (&creature_pool)[root_slot_idx].size = 65.0;
              (&creature_pool)[root_slot_idx].health = 3500.0;
              (&creature_pool)[root_slot_idx].move_speed = 1.5;
              (&creature_pool)[root_slot_idx].reward_value = 5000.0;
              (&creature_pool)[root_slot_idx].tint_a = 1.0;
              (&creature_pool)[root_slot_idx].tint_r = 0.9;
              (&creature_pool)[root_slot_idx].tint_g = 0.1;
              (&creature_pool)[root_slot_idx].tint_b = 0.1;
              (&creature_pool)[root_slot_idx].contact_damage = 0.0;
              goto LAB_004310b8;
            }
            if (template_id == 0x10) {
              (&creature_pool)[root_slot_idx].type_id = 2;
              (&creature_pool)[root_slot_idx].flags = 4;
              iVar7 = creature_spawn_slot_alloc();
              (&creature_pool)[root_slot_idx].link_index = iVar7;
              (&creature_spawn_slot_table)[iVar7].timer_s = 1.5;
              (&creature_spawn_slot_table)[iVar7].count = 0;
              (&creature_spawn_slot_table)[iVar7].limit = 100;
              (&creature_spawn_slot_table)[iVar7].interval_s = 2.3;
              (&creature_spawn_slot_table)[iVar7].template_id = 0x32;
              (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
              (&creature_pool)[root_slot_idx].size = 32.0;
              (&creature_pool)[root_slot_idx].health = 50.0;
              (&creature_pool)[root_slot_idx].move_speed = 2.8;
              (&creature_pool)[root_slot_idx].reward_value = 800.0;
            }
            else {
              if (template_id == 0xe) {
                (&creature_pool)[root_slot_idx].type_id = 2;
                (&creature_pool)[root_slot_idx].flags = 4;
                iVar7 = creature_spawn_slot_alloc();
                (&creature_pool)[root_slot_idx].link_index = iVar7;
                pos = (float *)0x0;
                (&creature_spawn_slot_table)[iVar7].timer_s = 1.5;
                (&creature_spawn_slot_table)[iVar7].count = 0;
                (&creature_spawn_slot_table)[iVar7].limit = 0x40;
                (&creature_spawn_slot_table)[iVar7].interval_s = 1.05;
                (&creature_spawn_slot_table)[iVar7].template_id = 0x1c;
                (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
                (&creature_pool)[root_slot_idx].size = 32.0;
                (&creature_pool)[root_slot_idx].health = 50.0;
                (&creature_pool)[root_slot_idx].move_speed = 2.8;
                (&creature_pool)[root_slot_idx].reward_value = 5000.0;
                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                (&creature_pool)[root_slot_idx].tint_r = 0.9;
                (&creature_pool)[root_slot_idx].tint_g = 0.8;
                (&creature_pool)[root_slot_idx].tint_b = 0.4;
                (&creature_pool)[root_slot_idx].contact_damage = 0.0;
                do {
                  iVar7 = creature_alloc_slot();
                  fVar11 = (float10)fcos((float10)(int)pos * (float10)0.2617994);
                  creature_ptr = &creature_pool + iVar7;
                  (&creature_pool)[iVar7].ai_mode = 3;
                  (&creature_pool)[iVar7].heading = 0.0;
                  (&creature_pool)[iVar7].anim_phase = 0.0;
                  (&creature_pool)[iVar7].link_index = root_slot_idx;
                  (&creature_pool)[iVar7].target_offset_x = (float)(fVar11 * (float10)100.0);
                  fVar11 = (float10)fsin((float10)(int)pos * (float10)0.2617994);
                  (&creature_pool)[iVar7].target_offset_y = (float)(fVar11 * (float10)100.0);
                  (&creature_pool)[iVar7].pos_x = *origin_pos_ptr;
                  (&creature_pool)[iVar7].pos_y = origin_pos_ptr[1];
                  (&creature_pool)[iVar7].vel_x = 0.0;
                  (&creature_pool)[iVar7].vel_y = 0.0;
                  (&creature_pool)[iVar7].collision_flag = '\0';
                  (&creature_pool)[iVar7].tint_r = 1.0;
                  (&creature_pool)[iVar7].health = 40.0;
                  (&creature_pool)[iVar7].max_health = 40.0;
                  (&creature_pool)[iVar7].tint_g = 0.3;
                  pos = (float *)((int)pos + 1);
                  (&creature_pool)[iVar7].tint_b = 0.3;
                  (&creature_pool)[iVar7].collision_timer = 0.0;
                  creature_ptr->active = '\x01';
                  (&creature_pool)[iVar7].state_flag = '\x01';
                  (&creature_pool)[iVar7].lifecycle_stage = 16.0;
                  (&creature_pool)[iVar7].attack_cooldown = 0.0;
                  (&creature_pool)[iVar7].type_id = 2;
                  (&creature_pool)[iVar7].move_speed = 4.0;
                  (&creature_pool)[iVar7].reward_value = 350.0;
                  (&creature_pool)[iVar7].tint_a = 1.0;
                  (&creature_pool)[iVar7].size = 35.0;
                  (&creature_pool)[iVar7].contact_damage = 30.0;
                } while ((int)pos < 0x18);
                goto LAB_004310b8;
              }
              if (template_id == 0xc) {
                (&creature_pool)[root_slot_idx].type_id = 2;
                (&creature_pool)[root_slot_idx].flags = 4;
                iVar7 = creature_spawn_slot_alloc();
                (&creature_pool)[root_slot_idx].link_index = iVar7;
                (&creature_spawn_slot_table)[iVar7].timer_s = 1.5;
                (&creature_spawn_slot_table)[iVar7].count = 0;
                (&creature_spawn_slot_table)[iVar7].limit = 100;
                (&creature_spawn_slot_table)[iVar7].interval_s = 2.0;
                (&creature_spawn_slot_table)[iVar7].template_id = 0x31;
                (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
                (&creature_pool)[root_slot_idx].size = 32.0;
                (&creature_pool)[root_slot_idx].health = 50.0;
                (&creature_pool)[root_slot_idx].move_speed = 2.8;
                (&creature_pool)[root_slot_idx].reward_value = 1000.0;
              }
              else {
                if (template_id != 0xd) {
                  if (template_id == 9) {
                    (&creature_pool)[root_slot_idx].type_id = 2;
                    (&creature_pool)[root_slot_idx].flags = 4;
                    iVar7 = creature_spawn_slot_alloc();
                    (&creature_pool)[root_slot_idx].link_index = iVar7;
                    (&creature_spawn_slot_table)[iVar7].timer_s = 1.0;
                    (&creature_spawn_slot_table)[iVar7].count = 0;
                    (&creature_spawn_slot_table)[iVar7].limit = 0x10;
                    (&creature_spawn_slot_table)[iVar7].interval_s = 2.0;
                    (&creature_spawn_slot_table)[iVar7].template_id = 0x1d;
                    (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
                    (&creature_pool)[root_slot_idx].size = 40.0;
                    (&creature_pool)[root_slot_idx].health = 450.0;
                    (&creature_pool)[root_slot_idx].move_speed = 2.0;
                    (&creature_pool)[root_slot_idx].reward_value = 1000.0;
                    (&creature_pool)[root_slot_idx].tint_a = 1.0;
                    (&creature_pool)[root_slot_idx].tint_r = 1.0;
                    (&creature_pool)[root_slot_idx].tint_g = 1.0;
                    (&creature_pool)[root_slot_idx].tint_b = 1.0;
                    (&creature_pool)[root_slot_idx].contact_damage = 0.0;
                    goto LAB_004310b8;
                  }
                  if (template_id == 7) {
                    (&creature_pool)[root_slot_idx].type_id = 2;
                    (&creature_pool)[root_slot_idx].flags = 4;
                    iVar7 = creature_spawn_slot_alloc();
                    (&creature_pool)[root_slot_idx].link_index = iVar7;
                    (&creature_spawn_slot_table)[iVar7].timer_s = 1.0;
                    (&creature_spawn_slot_table)[iVar7].count = 0;
                    (&creature_spawn_slot_table)[iVar7].limit = 100;
                    (&creature_spawn_slot_table)[iVar7].interval_s = 2.2;
                  }
                  else {
                    if (template_id != 8) {
                      /* Procedural baseline enemy families (size/health/tint randomized). */
                      if (template_id == 0x1a) {
                        (&creature_pool)[root_slot_idx].type_id = 2;
                        (&creature_pool)[root_slot_idx].size = 50.0;
                        (&creature_pool)[root_slot_idx].ai_mode = 1;
                        (&creature_pool)[root_slot_idx].health = 50.0;
                        (&creature_pool)[root_slot_idx].move_speed = 2.4;
                        (&creature_pool)[root_slot_idx].reward_value = 125.0;
                        (&creature_pool)[root_slot_idx].tint_a = 1.0;
                        iVar7 = crt_rand();
                        fVar4 = (float)(iVar7 % 0x28);
                      }
                      else if (template_id == 0x1b) {
                        (&creature_pool)[root_slot_idx].type_id = 3;
                        (&creature_pool)[root_slot_idx].size = 50.0;
                        (&creature_pool)[root_slot_idx].ai_mode = 1;
                        (&creature_pool)[root_slot_idx].health = 40.0;
                        (&creature_pool)[root_slot_idx].move_speed = 2.4;
                        (&creature_pool)[root_slot_idx].reward_value = 125.0;
                        (&creature_pool)[root_slot_idx].tint_a = 1.0;
                        iVar7 = crt_rand();
                        fVar4 = (float)(iVar7 % 0x28);
                      }
                      else {
                        if (template_id != 0x1c) {
                          /* Spawn-slot child templates (0x31+ range and add variants). */
                          if (template_id == 0x41) {
                            (&creature_pool)[root_slot_idx].type_id = 0;
                            iVar7 = crt_rand();
                            (&creature_pool)[root_slot_idx].tint_a = 1.0;
                            fVar4 = (float)(iVar7 % 0x1e + 0x28);
                            (&creature_pool)[root_slot_idx].size = fVar4;
                            (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 10.0;
                            (&creature_pool)[root_slot_idx].move_speed = fVar4 * 0.0025 + 0.9;
                            (&creature_pool)[root_slot_idx].reward_value = fVar4 + fVar4 + 50.0;
                            iVar7 = crt_rand();
                            fVar4 = (float)(iVar7 % 0x28) * 0.01 + 0.6;
                            (&creature_pool)[root_slot_idx].tint_r = fVar4;
                            (&creature_pool)[root_slot_idx].tint_g = fVar4;
                            (&creature_pool)[root_slot_idx].tint_b = fVar4;
                            iVar7 = crt_rand();
                            (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                            goto LAB_004310b8;
                          }
                          if (template_id == 0x31) {
                            (&creature_pool)[root_slot_idx].type_id = 1;
                            iVar7 = crt_rand();
                            fVar4 = (float)(iVar7 % 0x1e + 0x28);
                            (&creature_pool)[root_slot_idx].size = fVar4;
                            (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 10.0;
                            iVar7 = crt_rand();
                            (&creature_pool)[root_slot_idx].tint_a = 1.0;
                            (&creature_pool)[root_slot_idx].move_speed = (float)(iVar7 % 0x12) * 0.1 + 1.1;
                            (&creature_pool)[root_slot_idx].reward_value =
                                 (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size + 50.0;
                            iVar7 = crt_rand();
                            (&creature_pool)[root_slot_idx].tint_b = 0.38;
                            fVar4 = (float)(iVar7 % 0x1e) * 0.01 + 0.6;
                            (&creature_pool)[root_slot_idx].tint_r = fVar4;
                            (&creature_pool)[root_slot_idx].tint_g = fVar4;
                          }
                          else {
                            if (template_id != 0x32) {
                              if (template_id == 0x33) {
                                (&creature_pool)[root_slot_idx].type_id = 3;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0xf + 0x2d);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_g = 0.5;
                                (&creature_pool)[root_slot_idx].tint_b = 0.5;
                                (&creature_pool)[root_slot_idx].tint_r = (float)(iVar7 % 0x28) * 0.01 + 0.6;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x34) {
                                (&creature_pool)[root_slot_idx].type_id = 3;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0x14 + 0x28);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_r = 0.5;
                                (&creature_pool)[root_slot_idx].tint_b = 0.5;
                                (&creature_pool)[root_slot_idx].tint_g = (float)(iVar7 % 0x28) * 0.01 + 0.6;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x20) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0x1e + 0x28);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.3;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_b = 0.3;
                                (&creature_pool)[root_slot_idx].tint_g = (float)(iVar7 % 0x28) * 0.01 + 0.6;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 3) {
                                (&creature_pool)[root_slot_idx].type_id = 3;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0xf + 0x26);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.6;
                                (&creature_pool)[root_slot_idx].tint_g = 0.6;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_b = (float)(iVar7 % 0x19) * 0.01 + 0.8;
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_r) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_r) {
                                    (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_r = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_g) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_g) {
                                    (&creature_pool)[root_slot_idx].tint_g = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_g = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_b) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_b) {
                                    (&creature_pool)[root_slot_idx].tint_b = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_b = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_a) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_a) {
                                    (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_a = 0.0;
                                }
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 5) {
                                (&creature_pool)[root_slot_idx].type_id = 4;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0xf + 0x26);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.6;
                                (&creature_pool)[root_slot_idx].tint_g = 0.6;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_b = (float)(iVar7 % 0x19) * 0.01 + 0.8;
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_r) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_r) {
                                    (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_r = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_g) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_g) {
                                    (&creature_pool)[root_slot_idx].tint_g = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_g = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_b) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_b) {
                                    (&creature_pool)[root_slot_idx].tint_b = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_b = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_a) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_a) {
                                    (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_a = 0.0;
                                }
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 4) {
                                (&creature_pool)[root_slot_idx].type_id = 1;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0xf + 0x26);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.67;
                                (&creature_pool)[root_slot_idx].tint_g = 0.67;
                                (&creature_pool)[root_slot_idx].tint_b = 1.0;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 6) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0xf + 0x26);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.6;
                                (&creature_pool)[root_slot_idx].tint_g = 0.6;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_b = (float)(iVar7 % 0x19) * 0.01 + 0.8;
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_r) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_r) {
                                    (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_r = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_g) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_g) {
                                    (&creature_pool)[root_slot_idx].tint_g = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_g = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_b) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_b) {
                                    (&creature_pool)[root_slot_idx].tint_b = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_b = 0.0;
                                }
                                if (0.0 <= (&creature_pool)[root_slot_idx].tint_a) {
                                  if (1.0 < (&creature_pool)[root_slot_idx].tint_a) {
                                    (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                  }
                                }
                                else {
                                  (&creature_pool)[root_slot_idx].tint_a = 0.0;
                                }
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x35) {
                                (&creature_pool)[root_slot_idx].type_id = 4;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 10 + 0x1e);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].tint_b = 0.8;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_r = 0.8;
                                (&creature_pool)[root_slot_idx].tint_g = (float)(iVar7 % 0x14) * 0.01 + 0.8;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x2e) {
                                (&creature_pool)[root_slot_idx].type_id = 1;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0x1e + 0x28);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 20.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x12) * 0.1 + 1.1;
                                (&creature_pool)[root_slot_idx].reward_value =
                                     (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size +
                                     50.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_r = (float)(iVar7 % 0x28) * 0.01 + 0.6;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_g = (float)(iVar7 % 0x28) * 0.01 + 0.6;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_b = (float)(iVar7 % 0x28) * 0.01 + 0.6;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x36) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                (&creature_pool)[root_slot_idx].size = 50.0;
                                (&creature_pool)[root_slot_idx].ai_mode = 7;
                                (&creature_pool)[root_slot_idx].orbit_radius.projectile_type = 0x3fc00000;
                                (&creature_pool)[root_slot_idx].health = 10.0;
                                (&creature_pool)[root_slot_idx].move_speed = 1.8;
                                (&creature_pool)[root_slot_idx].reward_value = 150.0;
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_g = (float)(iVar7 % 5) * 0.01 + 0.65;
                                (&creature_pool)[root_slot_idx].tint_r = 0.65;
                                (&creature_pool)[root_slot_idx].tint_b = 0.95;
                                (&creature_pool)[root_slot_idx].contact_damage = 40.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x1d) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0x14 + 0x23);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 1.1428572 + 10.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0xf) * 0.1 + 1.1;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].reward_value = (float)(iVar7 % 100 + 0x32);
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_r = (float)(iVar7 % 0x32) * 0.001 + 0.6
                                ;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_g = (float)(iVar7 % 0x32) * 0.01 + 0.5;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_b = (float)(iVar7 % 0x32) * 0.001 + 0.6
                                ;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 10) + 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x1e) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0x1e + 0x23);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 2.2857144 + 10.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x11) * 0.1 + 1.5;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].reward_value = (float)(iVar7 % 200 + 0x32);
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_r = (float)(iVar7 % 0x32) * 0.001 + 0.6
                                ;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_g = (float)(iVar7 % 0x32) * 0.001 + 0.6
                                ;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_b = (float)(iVar7 % 0x32) * 0.01 + 0.5;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 0x1e) + 4.0
                                ;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x1f) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                iVar7 = crt_rand();
                                fVar4 = (float)(iVar7 % 0x1e + 0x2d);
                                (&creature_pool)[root_slot_idx].size = fVar4;
                                (&creature_pool)[root_slot_idx].health = fVar4 * 3.7142856 + 30.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].move_speed =
                                     (float)(iVar7 % 0x15) * 0.1 + 1.6;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].reward_value = (float)(iVar7 % 200 + 0x50);
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_r = (float)(iVar7 % 0x32) * 0.01 + 0.5;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_g = (float)(iVar7 % 0x32) * 0.001 + 0.6
                                ;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].tint_b = (float)(iVar7 % 0x32) * 0.001 + 0.6
                                ;
                                iVar7 = crt_rand();
                                (&creature_pool)[root_slot_idx].contact_damage = (float)(iVar7 % 0x23) + 8.0
                                ;
                                goto LAB_004310b8;
                              }
                              /* Fixed-stat encounter templates and special behavior flags. */
                              if (template_id == 0x24) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                (&creature_pool)[root_slot_idx].health = 20.0;
                                (&creature_pool)[root_slot_idx].move_speed = 2.0;
                                (&creature_pool)[root_slot_idx].reward_value = 110.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.1;
                                (&creature_pool)[root_slot_idx].tint_g = 0.7;
                                (&creature_pool)[root_slot_idx].tint_b = 0.11;
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].size = 50.0;
                                (&creature_pool)[root_slot_idx].contact_damage = 4.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x25) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                (&creature_pool)[root_slot_idx].health = 25.0;
                                (&creature_pool)[root_slot_idx].move_speed = 2.5;
                                (&creature_pool)[root_slot_idx].reward_value = 125.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.1;
                                (&creature_pool)[root_slot_idx].tint_g = 0.8;
                                (&creature_pool)[root_slot_idx].tint_b = 0.11;
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].size = 30.0;
                                (&creature_pool)[root_slot_idx].contact_damage = 3.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x26) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                (&creature_pool)[root_slot_idx].health = 50.0;
                                (&creature_pool)[root_slot_idx].move_speed = 2.2;
                                (&creature_pool)[root_slot_idx].reward_value = 125.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.6;
                                (&creature_pool)[root_slot_idx].tint_g = 0.8;
                                (&creature_pool)[root_slot_idx].tint_b = 0.6;
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                (&creature_pool)[root_slot_idx].size = 45.0;
                                (&creature_pool)[root_slot_idx].contact_damage = 10.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x27) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                (&creature_pool)[root_slot_idx].health = 50.0;
                                (&creature_pool)[root_slot_idx].move_speed = 2.1;
                                (&creature_pool)[root_slot_idx].flags = 0x400;
                                (&creature_pool)[root_slot_idx].reward_value = 125.0;
                                (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                (&creature_pool)[root_slot_idx].tint_g = 0.8;
                                (&creature_pool)[root_slot_idx].tint_b = 0.1;
                                (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                *(undefined2 *)&(&creature_pool)[root_slot_idx].link_index = 3;
                                *(undefined2 *)((int)&(&creature_pool)[root_slot_idx].link_index + 2) = 5;
                                (&creature_pool)[root_slot_idx].size = 45.0;
                                (&creature_pool)[root_slot_idx].contact_damage = 10.0;
                                goto LAB_004310b8;
                              }
                              if (template_id == 0x21) {
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                (&creature_pool)[root_slot_idx].health = 53.0;
                                (&creature_pool)[root_slot_idx].move_speed = 1.7;
                                (&creature_pool)[root_slot_idx].reward_value = 120.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.7;
                                (&creature_pool)[root_slot_idx].tint_g = 0.1;
                                (&creature_pool)[root_slot_idx].tint_b = 0.51;
                                local_4 = 0.5;
                              }
                              else {
                                if (template_id == 0x22) {
                                  (&creature_pool)[root_slot_idx].type_id = 2;
                                  (&creature_pool)[root_slot_idx].health = 25.0;
                                  (&creature_pool)[root_slot_idx].move_speed = 1.7;
                                  (&creature_pool)[root_slot_idx].reward_value = 150.0;
                                  (&creature_pool)[root_slot_idx].tint_r = 0.1;
                                  (&creature_pool)[root_slot_idx].tint_g = 0.7;
                                  (&creature_pool)[root_slot_idx].tint_b = 0.51;
                                  (&creature_pool)[root_slot_idx].tint_a = 0.05;
                                  (&creature_pool)[root_slot_idx].size = 50.0;
                                  (&creature_pool)[root_slot_idx].contact_damage = 8.0;
                                  goto LAB_004310b8;
                                }
                                if (template_id == 0x23) {
                                  (&creature_pool)[root_slot_idx].type_id = 2;
                                  (&creature_pool)[root_slot_idx].health = 5.0;
                                  (&creature_pool)[root_slot_idx].move_speed = 1.7;
                                  (&creature_pool)[root_slot_idx].reward_value = 180.0;
                                  (&creature_pool)[root_slot_idx].tint_r = 0.1;
                                  (&creature_pool)[root_slot_idx].tint_g = 0.7;
                                  (&creature_pool)[root_slot_idx].tint_b = 0.51;
                                  (&creature_pool)[root_slot_idx].tint_a = 0.04;
                                  (&creature_pool)[root_slot_idx].size = 45.0;
                                  (&creature_pool)[root_slot_idx].contact_damage = 8.0;
                                  goto LAB_004310b8;
                                }
                                if (template_id != 0x28) {
                                  if (template_id == 0x29) {
                                    (&creature_pool)[root_slot_idx].type_id = 2;
                                    (&creature_pool)[root_slot_idx].health = 800.0;
                                    (&creature_pool)[root_slot_idx].move_speed = 2.5;
                                    (&creature_pool)[root_slot_idx].reward_value = 450.0;
                                    (&creature_pool)[root_slot_idx].tint_r = 0.8;
                                    (&creature_pool)[root_slot_idx].tint_g = 0.8;
                                    (&creature_pool)[root_slot_idx].tint_b = 0.8;
                                    (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                    (&creature_pool)[root_slot_idx].size = 70.0;
                                    (&creature_pool)[root_slot_idx].contact_damage = 20.0;
                                    goto LAB_004310b8;
                                  }
                                  if (template_id == 0x2a) {
                                    (&creature_pool)[root_slot_idx].type_id = 2;
                                    (&creature_pool)[root_slot_idx].health = 50.0;
                                    (&creature_pool)[root_slot_idx].move_speed = 3.1;
                                    (&creature_pool)[root_slot_idx].reward_value = 300.0;
                                    (&creature_pool)[root_slot_idx].tint_r = 0.3;
                                    (&creature_pool)[root_slot_idx].tint_g = 0.3;
                                    (&creature_pool)[root_slot_idx].tint_b = 0.3;
                                    (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                    (&creature_pool)[root_slot_idx].size = 60.0;
                                    (&creature_pool)[root_slot_idx].contact_damage = 8.0;
                                    goto LAB_004310b8;
                                  }
                                  if (template_id == 0x2b) {
                                    (&creature_pool)[root_slot_idx].type_id = 2;
                                    (&creature_pool)[root_slot_idx].health = 30.0;
                                    (&creature_pool)[root_slot_idx].move_speed = 3.6;
                                    (&creature_pool)[root_slot_idx].reward_value = 450.0;
                                    (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                    (&creature_pool)[root_slot_idx].tint_g = 0.3;
                                    (&creature_pool)[root_slot_idx].tint_b = 0.3;
                                  }
                                  else {
                                    if (template_id == 0x2c) {
                                      (&creature_pool)[root_slot_idx].type_id = 2;
                                      (&creature_pool)[root_slot_idx].health = 3800.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 2.0;
                                      (&creature_pool)[root_slot_idx].reward_value = 1500.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 0.85;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.2;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.2;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      (&creature_pool)[root_slot_idx].size = 80.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 40.0;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x2d) {
                                      (&creature_pool)[root_slot_idx].type_id = 2;
                                      (&creature_pool)[root_slot_idx].health = 45.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 3.1;
                                      (&creature_pool)[root_slot_idx].reward_value = 200.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 0.0;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.9;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.8;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      (&creature_pool)[root_slot_idx].size = 38.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 3.0;
                                      (&creature_pool)[root_slot_idx].ai_mode = 2;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x2f) {
                                      (&creature_pool)[root_slot_idx].type_id = 1;
                                      (&creature_pool)[root_slot_idx].health = 20.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 2.5;
                                      (&creature_pool)[root_slot_idx].reward_value = 150.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 0.8;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.8;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.8;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      (&creature_pool)[root_slot_idx].size = 45.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 4.0;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x30) {
                                      (&creature_pool)[root_slot_idx].type_id = 1;
                                      (&creature_pool)[root_slot_idx].health = 1000.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 2.0;
                                      (&creature_pool)[root_slot_idx].reward_value = 400.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 0.9;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.8;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.1;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      (&creature_pool)[root_slot_idx].size = 65.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 10.0;
                                      goto LAB_004310b8;
                                    }
                                    /* Late-game boss/special templates (0x3b-0x43). */
                                    if (template_id == 0x3b) {
                                      (&creature_pool)[root_slot_idx].type_id = 3;
                                      (&creature_pool)[root_slot_idx].health = 1200.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 2.0;
                                      (&creature_pool)[root_slot_idx].reward_value = 4000.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 0.9;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.0;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.0;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      (&creature_pool)[root_slot_idx].size = 70.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 20.0;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x3c) {
                                      (&creature_pool)[root_slot_idx].type_id = 3;
                                      (&creature_pool)[root_slot_idx].flags = 0x100;
                                      (&creature_pool)[root_slot_idx].orbit_angle = 0.4;
                                      (&creature_pool)[root_slot_idx].orbit_radius.projectile_type =
                                           PROJECTILE_TYPE_SPIDER_PLASMA;
                                      (&creature_pool)[root_slot_idx].health = 200.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 2.0;
                                      (&creature_pool)[root_slot_idx].reward_value = 200.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 0.9;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.1;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.1;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      (&creature_pool)[root_slot_idx].size = 40.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 20.0;
                                      (&creature_pool)[root_slot_idx].ai_mode = 2;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x3d) {
                                      (&creature_pool)[root_slot_idx].type_id = 3;
                                      (&creature_pool)[root_slot_idx].health = 70.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 2.6;
                                      (&creature_pool)[root_slot_idx].reward_value = 120.0;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      iVar7 = crt_rand();
                                      fVar4 = (float)(iVar7 % 0x14) * 0.01 + 0.8;
                                      (&creature_pool)[root_slot_idx].tint_r = fVar4;
                                      (&creature_pool)[root_slot_idx].tint_b = fVar4;
                                      (&creature_pool)[root_slot_idx].tint_g = fVar4;
                                      iVar7 = crt_rand();
                                      fVar4 = (float)(iVar7 % 7 + 0x2d);
                                      (&creature_pool)[root_slot_idx].size = fVar4;
                                      (&creature_pool)[root_slot_idx].contact_damage = fVar4 * 0.22;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x3e) {
                                      (&creature_pool)[root_slot_idx].type_id = 3;
                                      (&creature_pool)[root_slot_idx].health = 1000.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 2.8;
                                      (&creature_pool)[root_slot_idx].reward_value = 500.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_g = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_b = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      (&creature_pool)[root_slot_idx].size = 64.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 40.0;
                                      goto LAB_004310b8;
                                    }
                                    /* Campaign apex root template with an internal spawn slot. */
                                    if (template_id == 0) {
                                      (&creature_pool)[root_slot_idx].type_id = 0;
                                      (&creature_pool)[root_slot_idx].flags = 0x44;
                                      (&creature_pool)[root_slot_idx].health = 8500.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 1.3;
                                      (&creature_pool)[root_slot_idx].reward_value = 6600.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 0.6;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.6;
                                      (&creature_pool)[root_slot_idx].tint_b = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_a = 0.8;
                                      (&creature_pool)[root_slot_idx].size = 64.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 50.0;
                                      iVar7 = creature_spawn_slot_alloc();
                                      (&creature_pool)[root_slot_idx].link_index = iVar7;
                                      (&creature_spawn_slot_table)[iVar7].timer_s = 1.0;
                                      (&creature_spawn_slot_table)[iVar7].count = 0;
                                      (&creature_spawn_slot_table)[iVar7].limit = 0x32c;
                                      (&creature_spawn_slot_table)[iVar7].interval_s = 0.7;
                                      (&creature_spawn_slot_table)[iVar7].template_id = 0x41;
                                      (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x38) {
                                      (&creature_pool)[root_slot_idx].type_id = 3;
                                      (&creature_pool)[root_slot_idx].flags = 0x80;
                                      (&creature_pool)[root_slot_idx].link_index = 0;
                                      (&creature_pool)[root_slot_idx].health = 50.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 4.8;
                                      (&creature_pool)[root_slot_idx].reward_value = 433.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.75;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.1;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      rng_value = crt_rand();
                                      rng_value = rng_value & 0x80000003;
                                      if ((int)rng_value < 0) {
                                        rng_value = (rng_value - 1 | 0xfffffffc) + 1;
                                      }
                                      (&creature_pool)[root_slot_idx].size = (float)(int)(rng_value + 0x29);
                                      (&creature_pool)[root_slot_idx].contact_damage = 10.0;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x37) {
                                      (&creature_pool)[root_slot_idx].type_id = 4;
                                      (&creature_pool)[root_slot_idx].flags = 0x100;
                                      (&creature_pool)[root_slot_idx].link_index = 0;
                                      (&creature_pool)[root_slot_idx].health = 50.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 3.2;
                                      (&creature_pool)[root_slot_idx].reward_value = 433.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.75;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.1;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      rng_value = crt_rand();
                                      rng_value = rng_value & 0x80000003;
                                      if ((int)rng_value < 0) {
                                        rng_value = (rng_value - 1 | 0xfffffffc) + 1;
                                      }
                                      (&creature_pool)[root_slot_idx].size = (float)(int)(rng_value + 0x29);
                                      (&creature_pool)[root_slot_idx].contact_damage = 10.0;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x39) {
                                      (&creature_pool)[root_slot_idx].type_id = 3;
                                      (&creature_pool)[root_slot_idx].flags = 0x80;
                                      (&creature_pool)[root_slot_idx].link_index = 0;
                                      (&creature_pool)[root_slot_idx].health = 4.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 4.8;
                                      (&creature_pool)[root_slot_idx].reward_value = 50.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 0.8;
                                      (&creature_pool)[root_slot_idx].tint_g = 0.65;
                                      (&creature_pool)[root_slot_idx].tint_b = 0.1;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      rng_value = crt_rand();
                                      rng_value = rng_value & 0x80000003;
                                      if ((int)rng_value < 0) {
                                        rng_value = (rng_value - 1 | 0xfffffffc) + 1;
                                      }
                                      (&creature_pool)[root_slot_idx].size = (float)(int)(rng_value + 0x1a);
                                      (&creature_pool)[root_slot_idx].contact_damage = 10.0;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id == 0x3a) {
                                      (&creature_pool)[root_slot_idx].type_id = 3;
                                      (&creature_pool)[root_slot_idx].flags = 0x10;
                                      (&creature_pool)[root_slot_idx].orbit_angle = 0.9;
                                      (&creature_pool)[root_slot_idx].orbit_radius.projectile_type =
                                           PROJECTILE_TYPE_PLASMA_RIFLE;
                                      (&creature_pool)[root_slot_idx].health = 4500.0;
                                      (&creature_pool)[root_slot_idx].move_speed = 2.0;
                                      (&creature_pool)[root_slot_idx].reward_value = 4500.0;
                                      (&creature_pool)[root_slot_idx].tint_r = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_g = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_b = 1.0;
                                      (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                      (&creature_pool)[root_slot_idx].size = 64.0;
                                      (&creature_pool)[root_slot_idx].contact_damage = 50.0;
                                      goto LAB_004310b8;
                                    }
                                    if (template_id != 0x3f) {
                                      if (template_id == 0x40) {
                                        (&creature_pool)[root_slot_idx].type_id = 3;
                                        (&creature_pool)[root_slot_idx].health = 70.0;
                                        (&creature_pool)[root_slot_idx].move_speed = 2.2;
                                        (&creature_pool)[root_slot_idx].reward_value = 160.0;
                                        (&creature_pool)[root_slot_idx].tint_r = 0.5;
                                        (&creature_pool)[root_slot_idx].tint_g = 0.6;
                                        (&creature_pool)[root_slot_idx].tint_b = 0.9;
                                        (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                        (&creature_pool)[root_slot_idx].size = 45.0;
                                        (&creature_pool)[root_slot_idx].contact_damage = 5.0;
                                        goto LAB_004310b8;
                                      }
                                      if (template_id == 0x42) {
                                        (&creature_pool)[root_slot_idx].type_id = 0;
                                        (&creature_pool)[root_slot_idx].health = 200.0;
                                        (&creature_pool)[root_slot_idx].move_speed = 1.7;
                                        (&creature_pool)[root_slot_idx].reward_value = 160.0;
                                        (&creature_pool)[root_slot_idx].tint_r = 0.9;
                                        (&creature_pool)[root_slot_idx].tint_g = 0.9;
                                        (&creature_pool)[root_slot_idx].tint_b = 0.9;
                                        (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                        (&creature_pool)[root_slot_idx].size = 45.0;
                                        (&creature_pool)[root_slot_idx].contact_damage = 15.0;
                                        goto LAB_004310b8;
                                      }
                                      if (template_id == 0x43) {
                                        (&creature_pool)[root_slot_idx].type_id = 0;
                                        (&creature_pool)[root_slot_idx].health = 2000.0;
                                        (&creature_pool)[root_slot_idx].move_speed = 2.1;
                                        (&creature_pool)[root_slot_idx].reward_value = 460.0;
                                        (&creature_pool)[root_slot_idx].tint_r = 0.2;
                                        (&creature_pool)[root_slot_idx].tint_g = 0.6;
                                        (&creature_pool)[root_slot_idx].tint_b = 0.1;
                                        (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                        (&creature_pool)[root_slot_idx].size = 70.0;
                                        (&creature_pool)[root_slot_idx].contact_damage = 15.0;
                                        goto LAB_004310b8;
                                      }
                                      goto LAB_00431094;
                                    }
                                    (&creature_pool)[root_slot_idx].type_id = 3;
                                    (&creature_pool)[root_slot_idx].health = 200.0;
                                    (&creature_pool)[root_slot_idx].move_speed = 2.3;
                                    (&creature_pool)[root_slot_idx].reward_value = 210.0;
                                    (&creature_pool)[root_slot_idx].tint_r = 0.7;
                                    (&creature_pool)[root_slot_idx].tint_g = 0.4;
                                    (&creature_pool)[root_slot_idx].tint_b = 0.1;
                                  }
                                  (&creature_pool)[root_slot_idx].tint_a = 1.0;
                                  (&creature_pool)[root_slot_idx].size = 35.0;
                                  (&creature_pool)[root_slot_idx].contact_damage = 20.0;
                                  goto LAB_004310b8;
                                }
                                (&creature_pool)[root_slot_idx].type_id = 2;
                                (&creature_pool)[root_slot_idx].health = 50.0;
                                (&creature_pool)[root_slot_idx].move_speed = 1.7;
                                (&creature_pool)[root_slot_idx].reward_value = 150.0;
                                (&creature_pool)[root_slot_idx].tint_r = 0.7;
                                local_4 = 1.0;
                                (&creature_pool)[root_slot_idx].tint_g = 0.1;
                                (&creature_pool)[root_slot_idx].tint_b = 0.51;
                              }
                              (&creature_pool)[root_slot_idx].tint_a = local_4;
                              (&creature_pool)[root_slot_idx].size = 55.0;
                              (&creature_pool)[root_slot_idx].contact_damage = 8.0;
                              goto LAB_004310b8;
                            }
                            (&creature_pool)[root_slot_idx].type_id = 3;
                            iVar7 = crt_rand();
                            fVar4 = (float)(iVar7 % 0x19 + 0x28);
                            (&creature_pool)[root_slot_idx].size = fVar4;
                            (&creature_pool)[root_slot_idx].health = fVar4 + 10.0;
                            iVar7 = crt_rand();
                            (&creature_pool)[root_slot_idx].tint_a = 1.0;
                            (&creature_pool)[root_slot_idx].move_speed = (float)(iVar7 % 0x11) * 0.1 + 1.1;
                            (&creature_pool)[root_slot_idx].reward_value =
                                 (&creature_pool)[root_slot_idx].size + (&creature_pool)[root_slot_idx].size + 50.0;
                            iVar7 = crt_rand();
                            fVar4 = (float)(iVar7 % 0x28) * 0.01 + 0.6;
                            (&creature_pool)[root_slot_idx].tint_r = fVar4;
                            (&creature_pool)[root_slot_idx].tint_g = fVar4;
                            (&creature_pool)[root_slot_idx].tint_b = fVar4;
                          }
                          (&creature_pool)[root_slot_idx].contact_damage =
                               (&creature_pool)[root_slot_idx].size * 0.14 + 4.0;
                          goto LAB_004310b8;
                        }
                        (&creature_pool)[root_slot_idx].type_id = 1;
                        (&creature_pool)[root_slot_idx].size = 50.0;
                        (&creature_pool)[root_slot_idx].ai_mode = 1;
                        (&creature_pool)[root_slot_idx].health = 50.0;
                        (&creature_pool)[root_slot_idx].move_speed = 2.4;
                        (&creature_pool)[root_slot_idx].reward_value = 125.0;
                        (&creature_pool)[root_slot_idx].tint_a = 1.0;
                        iVar7 = crt_rand();
                        fVar4 = (float)(iVar7 % 0x28);
                      }
                      fVar4 = fVar4 * 0.01 + 0.5;
                      (&creature_pool)[root_slot_idx].tint_r = fVar4;
                      (&creature_pool)[root_slot_idx].tint_g = fVar4;
                      (&creature_pool)[root_slot_idx].tint_b = 1.0;
                      (&creature_pool)[root_slot_idx].contact_damage = 5.0;
                      goto LAB_004310b8;
                    }
                    (&creature_pool)[root_slot_idx].type_id = 2;
                    (&creature_pool)[root_slot_idx].flags = 4;
                    iVar7 = creature_spawn_slot_alloc();
                    (&creature_pool)[root_slot_idx].link_index = iVar7;
                    (&creature_spawn_slot_table)[iVar7].timer_s = 1.0;
                    (&creature_spawn_slot_table)[iVar7].count = 0;
                    (&creature_spawn_slot_table)[iVar7].limit = 100;
                    (&creature_spawn_slot_table)[iVar7].interval_s = 2.8;
                  }
                  (&creature_spawn_slot_table)[iVar7].template_id = 0x1d;
                  (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
                  (&creature_pool)[root_slot_idx].size = 50.0;
                  (&creature_pool)[root_slot_idx].health = 1000.0;
                  (&creature_pool)[root_slot_idx].move_speed = 2.0;
                  (&creature_pool)[root_slot_idx].reward_value = 3000.0;
                  (&creature_pool)[root_slot_idx].tint_a = 1.0;
                  (&creature_pool)[root_slot_idx].tint_r = 1.0;
                  (&creature_pool)[root_slot_idx].tint_g = 1.0;
                  (&creature_pool)[root_slot_idx].tint_b = 1.0;
                  (&creature_pool)[root_slot_idx].contact_damage = 0.0;
                  goto LAB_004310b8;
                }
                (&creature_pool)[root_slot_idx].type_id = 2;
                (&creature_pool)[root_slot_idx].flags = 4;
                iVar7 = creature_spawn_slot_alloc();
                (&creature_pool)[root_slot_idx].link_index = iVar7;
                (&creature_spawn_slot_table)[iVar7].timer_s = 2.0;
                (&creature_spawn_slot_table)[iVar7].count = 0;
                (&creature_spawn_slot_table)[iVar7].limit = 100;
                (&creature_spawn_slot_table)[iVar7].interval_s = 6.0;
                (&creature_spawn_slot_table)[iVar7].template_id = 0x31;
                (&creature_spawn_slot_table)[iVar7].owner = creature_ptr;
                (&creature_pool)[root_slot_idx].size = 32.0;
                (&creature_pool)[root_slot_idx].health = 50.0;
                (&creature_pool)[root_slot_idx].move_speed = 1.3;
                (&creature_pool)[root_slot_idx].reward_value = 1000.0;
              }
            }
            (&creature_pool)[root_slot_idx].tint_a = 1.0;
            (&creature_pool)[root_slot_idx].tint_r = 0.9;
            (&creature_pool)[root_slot_idx].tint_g = 0.8;
            (&creature_pool)[root_slot_idx].tint_b = 0.4;
            (&creature_pool)[root_slot_idx].contact_damage = 0.0;
            goto LAB_004310b8;
          }
          (&creature_pool)[root_slot_idx].type_id = 2;
          (&creature_pool)[root_slot_idx].pos_x = *pos;
          (&creature_pool)[root_slot_idx].pos_y = pos[1];
          (&creature_pool)[root_slot_idx].type_id = 2;
          (&creature_pool)[root_slot_idx].tint_r = 0.66499996;
          (&creature_pool)[root_slot_idx].tint_g = 0.385;
          (&creature_pool)[root_slot_idx].ai_mode = 0;
          (&creature_pool)[root_slot_idx].health = 20.0;
          (&creature_pool)[root_slot_idx].tint_b = 0.259;
          (&creature_pool)[root_slot_idx].move_speed = 2.9;
          (&creature_pool)[root_slot_idx].reward_value = 60.0;
          (&creature_pool)[root_slot_idx].tint_a = 0.56;
          (&creature_pool)[root_slot_idx].size = 50.0;
          (&creature_pool)[root_slot_idx].contact_damage = 35.0;
          (&creature_pool)[root_slot_idx].max_health = 20.0;
        }
        goto LAB_00431094;
      }
      /* Template 0x13: serpent-style linked chain rooted on an orbit anchor. */
      (&creature_pool)[root_slot_idx].type_id = 2;
      iVar7 = _terrain_texture_height / 2;
      (&creature_pool)[root_slot_idx].ai_mode = 2;
      (&creature_pool)[root_slot_idx].pos_x = -10.0;
      fVar11 = (float10)fcos((float10)0.0);
      (&creature_pool)[root_slot_idx].tint_r = 0.6;
      (&creature_pool)[root_slot_idx].pos_y = (float)iVar7;
      (&creature_pool)[root_slot_idx].tint_g = 0.8;
      (&creature_pool)[root_slot_idx].tint_b = 0.91;
      (&creature_pool)[root_slot_idx].health = 200.0;
      (&creature_pool)[root_slot_idx].move_speed = 2.0;
      (&creature_pool)[root_slot_idx].reward_value = 600.0;
      (&creature_pool)[root_slot_idx].tint_a = 1.0;
      (&creature_pool)[root_slot_idx].size = 40.0;
      (&creature_pool)[root_slot_idx].contact_damage = 20.0;
      pos = (float *)0x2;
      fVar12 = (float10)fsin((float10)0.0);
      fVar4 = *origin_pos_ptr;
      fVar1 = origin_pos_ptr[1];
      (&creature_pool)[root_slot_idx].max_health = 200.0;
      (&creature_pool)[root_slot_idx].pos_x = (float)(fVar11 * (float10)256.0 + (float10)fVar4);
      (&creature_pool)[root_slot_idx].ai_mode = 6;
      (&creature_pool)[root_slot_idx].pos_y = (float)fVar12 * 256.0 + fVar1;
      iVar7 = root_slot_idx;
      do {
        child_slot_idx = creature_alloc_slot();
        fVar11 = (float10)fcos((float10)(int)pos * (float10)0.34906587);
        creature_ptr = &creature_pool + child_slot_idx;
        (&creature_pool)[child_slot_idx].ai_mode = 6;
        (&creature_pool)[child_slot_idx].link_index = iVar7;
        (&creature_pool)[child_slot_idx].orbit_angle = 3.1415927;
        (&creature_pool)[child_slot_idx].orbit_radius.projectile_type = 0x41200000;
        fVar12 = (float10)fsin((float10)(int)pos * (float10)0.34906587);
        fVar4 = origin_pos_ptr[1];
        (&creature_pool)[child_slot_idx].pos_x = (float)fVar11 * 256.0 + *origin_pos_ptr;
        (&creature_pool)[child_slot_idx].vel_x = 0.0;
        (&creature_pool)[child_slot_idx].health = 60.0;
        (&creature_pool)[child_slot_idx].pos_y = (float)(fVar12 * (float10)256.0 + (float10)fVar4);
        (&creature_pool)[child_slot_idx].vel_y = 0.0;
        (&creature_pool)[child_slot_idx].reward_value = 60.0;
        (&creature_pool)[child_slot_idx].max_health = 60.0;
        (&creature_pool)[child_slot_idx].tint_r = 0.4;
        pos = (float *)((int)pos + 2);
        (&creature_pool)[child_slot_idx].tint_g = 0.7;
        (&creature_pool)[child_slot_idx].collision_flag = '\0';
        (&creature_pool)[child_slot_idx].tint_b = 0.11;
        (&creature_pool)[child_slot_idx].collision_timer = 0.0;
        creature_ptr->active = '\x01';
        (&creature_pool)[child_slot_idx].tint_a = 1.0;
        (&creature_pool)[child_slot_idx].state_flag = '\x01';
        (&creature_pool)[child_slot_idx].lifecycle_stage = 16.0;
        (&creature_pool)[child_slot_idx].attack_cooldown = 0.0;
        (&creature_pool)[child_slot_idx].type_id = 2;
        (&creature_pool)[child_slot_idx].move_speed = 2.0;
        (&creature_pool)[child_slot_idx].size = 50.0;
        (&creature_pool)[child_slot_idx].contact_damage = 4.0;
        iVar7 = child_slot_idx;
      } while ((int)pos < 0x16);
    }
    (&creature_pool)[root_slot_idx].link_index = child_slot_idx;
  }
LAB_00431094:
  /* Unknown template_id fallback keeps game running and emits console diagnostics. */
  creature_ptr->type_id = 2;
  creature_ptr->health = 20.0;
  console_printf(&console_log_queue,s_Unhandled_creatureType__00477758);
LAB_004310b8:
  /* Shared post-dispatch normalization and difficulty scaling adjustments. */
  if ((((demo_mode_active == '\0') && (0.0 < creature_ptr->pos_x)) &&
      (creature_ptr->pos_x < (float)_terrain_texture_width)) &&
     ((0.0 < creature_ptr->pos_y && (creature_ptr->pos_y < (float)_terrain_texture_height)))) {
    effect_spawn_burst(&creature_ptr->pos_x,8);
  }
  creature_ptr->max_health = creature_ptr->health;
  rng_value = creature_ptr->flags;
  if ((((rng_value & 0x10) == 0) && (creature_ptr->type_id == 3)) && ((rng_value & 0x80) == 0)) {
    creature_ptr->flags = rng_value | 0x80;
    creature_ptr->link_index = 0;
    creature_ptr->move_speed = creature_ptr->move_speed * 1.2;
  }
  if ((template_id == 0x38) && (config_hardcore != '\0')) {
    creature_ptr->move_speed = creature_ptr->move_speed * 0.7;
  }
  creature_ptr->heading = heading;
  /* Non-hardcore branch applies quest retry dampening, hardcore boosts stats instead. */
  if ((config_hardcore == '\0') &&
     (((creature_ptr->flags & 4) == 0 ||
      ((&creature_spawn_slot_table)[creature_ptr->link_index].interval_s =
            (&creature_spawn_slot_table)[creature_ptr->link_index].interval_s + 0.2,
      config_hardcore == '\0')))) {
    if (0 < quest_fail_retry_count) {
      switch(quest_fail_retry_count) {
      case 1:
        creature_ptr->reward_value = creature_ptr->reward_value * 0.9;
        creature_ptr->move_speed = creature_ptr->move_speed * 0.95;
        creature_ptr->contact_damage = creature_ptr->contact_damage * 0.95;
        fVar4 = creature_ptr->health * 0.95;
        break;
      case 2:
        creature_ptr->reward_value = creature_ptr->reward_value * 0.85;
        creature_ptr->move_speed = creature_ptr->move_speed * 0.9;
        creature_ptr->contact_damage = creature_ptr->contact_damage * 0.9;
        fVar4 = creature_ptr->health * 0.9;
        break;
      case 3:
        creature_ptr->reward_value = creature_ptr->reward_value * 0.85;
        creature_ptr->move_speed = creature_ptr->move_speed * 0.8;
        creature_ptr->contact_damage = creature_ptr->contact_damage * 0.8;
        fVar4 = creature_ptr->health * 0.8;
        break;
      case 4:
        creature_ptr->reward_value = creature_ptr->reward_value * 0.8;
        creature_ptr->move_speed = creature_ptr->move_speed * 0.7;
        creature_ptr->contact_damage = creature_ptr->contact_damage * 0.7;
        fVar4 = creature_ptr->health * 0.7;
        break;
      default:
        creature_ptr->reward_value = creature_ptr->reward_value * 0.8;
        creature_ptr->move_speed = creature_ptr->move_speed * 0.6;
        creature_ptr->contact_damage = creature_ptr->contact_damage * 0.5;
        fVar4 = creature_ptr->health * 0.5;
      }
      creature_ptr->health = fVar4;
      if ((creature_ptr->flags & 4) != 0) {
        fVar4 = (float)quest_fail_retry_count * 0.35;
        if (3.0 < fVar4) {
          fVar4 = 3.0;
        }
        (&creature_spawn_slot_table)[creature_ptr->link_index].interval_s =
             fVar4 + (&creature_spawn_slot_table)[creature_ptr->link_index].interval_s;
      }
    }
  }
  else {
    quest_fail_retry_count = 0;
    creature_ptr->move_speed = creature_ptr->move_speed * 1.05;
    creature_ptr->contact_damage = creature_ptr->contact_damage * 1.4;
    creature_ptr->health = creature_ptr->health * 1.2;
    if ((creature_ptr->flags & 4) != 0) {
      root_slot_idx = creature_ptr->link_index;
      fVar4 = (&creature_spawn_slot_table)[root_slot_idx].interval_s - 0.2;
      (&creature_spawn_slot_table)[root_slot_idx].interval_s = fVar4;
      if (fVar4 < 0.1) {
        (&creature_spawn_slot_table)[root_slot_idx].interval_s = 0.1;
        return creature_ptr;
      }
    }
  }
  return creature_ptr;
}



/*
