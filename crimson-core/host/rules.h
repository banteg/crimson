#pragma once
// The run's bug policy, Python's `RunSpec.preserve_bugs`: nonzero keeps the
// original's bugs, zero applies the documented fixes (the ranked rules).
extern "C" unsigned char portable_preserve_bugs;
extern "C" unsigned int portable_rules, portable_legacy_coop_reload;
#define portable_rules2_fixes (portable_rules >= 2 && !portable_preserve_bugs)
// The original build whose rules the run plays, Python's `RunSpec.cl_build` (src/crimson/cl_build.py): 1.9.93, which
// the sources compile as (CL_BUILD), or 1.9.8, whose rule guards editions/ turns into branches on these, as
// GameplayState's `rules_1_9_8` and `bugs_1_9_8` (1.9.8's own bugs, kept only with preserve_bugs).
enum : unsigned { PORTABLE_CL_BUILD_1_9_8 = 10908, PORTABLE_CL_BUILD_1_9_93 = 10993 };
extern "C" unsigned int portable_cl_build;
#define portable_rules_1_9_8 (portable_cl_build == PORTABLE_CL_BUILD_1_9_8)
#define portable_bugs_1_9_8 (portable_rules_1_9_8 && portable_preserve_bugs)
// What the game derives from the build once, at startup: the perk range perks_init_database sets
// (editions/04-perks.patch), which changes with the build wherever a run sets it (host.cpp portable_profile_set).
extern "C" void portable_perk_range(void);
// Each weapon's shot sound, and a sound global, as its audio_asset_id_table slot (host.cpp): 1.9.8's Fire Bullets
// reroll compares these where the original compares loaded ids (editions/02-fire-bullets-reroll.patch).
extern "C" int portable_weapon_shot_slot[64];
extern "C" int portable_sound_slot(const int *sound);
// Added run state lives outside the recovered player_t layout.
struct PortablePlayerRules {
  float fire_cough_interval, hot_tempered_interval;
  int alt_weapon_swap_cooldown_ms;
};
extern "C" PortablePlayerRules portable_player_rules[2];
extern "C" float portable_impact_heading(float x, float y);
