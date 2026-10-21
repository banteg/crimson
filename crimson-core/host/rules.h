#pragma once
// The run's bug policy, Python's `RunSpec.preserve_bugs`: nonzero keeps the
// original's bugs, zero applies the documented fixes (the ranked rules).
extern "C" unsigned char portable_preserve_bugs;
// Added run state lives outside the recovered player_t layout.
struct PortablePlayerRules {
  float fire_cough_interval, hot_tempered_interval;
  int alt_weapon_swap_cooldown_ms;
};
extern "C" PortablePlayerRules portable_player_rules[2];
extern "C" float portable_impact_heading(float x, float y);
