#include <math.h>

#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"
#include "grim2d_cpp.h"

struct vec2_t : vec2f_t {
    vec2_t() {}
    vec2_t(float _x, float _y) { x = _x; y = _y; }

    inline vec2_t operator - (const vec2_t &v)
    {
        return vec2_t (x - v.x, y - v.y);
    }

    inline vec2_t operator + (const vec2_t &v)
    {
        return vec2_t (x + v.x, y + v.y);
    }

    inline vec2_t& operator += (const vec2_t &v)
    {
        x += v.x;
        y += v.y;
        return *this;
    }

    vec2_t vec2_sub(const vec2_t &v);
};

typedef vec2_t player_update_vec2_t;

inline vec2_t pu_polar (const float &angle, const float &radius)
{
	return vec2_t (cosf(angle) * radius, sinf(angle) * radius);
}

inline float VEC2_Length (const vec2_t &v)
{
	return sqrtf(v.x * v.x + v.y * v.y);
}
inline float VEC2_Length2 (const vec2_t &v)
{
	float squared = v.x * v.x;
	squared += v.y * v.y;
	return sqrtf(squared);
}

inline float VEC2_Angle (const vec2_t &v)
{
	return atan2f(v.y, v.x);
}

inline vec2_t operator * (const vec2_t &v, float s)
{	return vec2_t (s * v.x, s * v.y);	}

inline vec2_t operator * (float s, const vec2_t &v)
{	return vec2_t (s * v.x, s * v.y);	}

extern "C" {
extern unsigned char console_open_flag;
extern unsigned char time_scale_active;
extern IGrim2D_cpp *grim_interface_ptr;
extern player_aim_screen_xy_t player_aim_screen_x;
extern float time_scale_factor;
extern float perk_man_bomb_trigger_interval_s;
extern float perk_fire_cough_trigger_interval_s;
extern float perk_hot_tempered_trigger_interval_s;
extern float player_spread_damping_gate;
extern float player_spread_damping_scalar;
extern int perk_id_sharpshooter;
extern int perk_id_anxious_loader;
extern int perk_id_stationary_reloader;
extern int perk_id_angry_reloader;
extern int perk_id_long_distance_runner;
extern int perk_id_hot_tempered;
extern int perk_id_fastshot;
extern int config_movement_schemes[];
extern int config_aim_schemes[];
extern int config_player_count;
extern int config_key_reload;
extern int player2_move_key_forward;
extern int player2_move_key_backward;
extern int player2_turn_key_left;
extern int player2_turn_key_right;
extern float camera_offset_x;
extern float camera_offset_y;
extern cvar_float_t *cv_padAimDistMul;
extern int frame_dt_ms;
extern int player_alt_weapon_swap_cooldown_ms;
extern unsigned char survival_reward_fire_seen;
extern weapon_storage_entry_t weapon_ammo_class[];
extern int sfx_bloodspill_01;
extern int sfx_explosion_small;
extern int fire_bullets_primary_shot_sfx_id;
extern int fire_bullets_secondary_shot_sfx_id;
extern float fire_bullets_fallback_shot_cooldown;
extern float fire_bullets_fallback_spread_heat;

void effect_spawn_blood_splatter(
    const vec2f_t *pos,
    float angle,
    float age);
float vec2_length(const vec2f_t *v);
int fx_spawn_sprite(
    const vec2f_t *pos,
    const vec2f_t *vel,
    float scale);
bool input_primary_just_pressed(void);
bool input_aim_pov_left_active(void);
bool input_aim_pov_right_active(void);
float player_heading_approach_target(float target_heading);
vec2f_t *__stdcall D3DXVec2Normalize(
    vec2f_t *dst,
    const vec2f_t *src);
void player_start_reload(void);
void player_take_damage(int player_index, float damage);
int fx_spawn_particle(
    const vec2f_t *pos,
    float angle,
    const vec2f_t *move,
    float intensity);
int fx_spawn_particle_slow(
    const vec2f_t *pos,
    float angle,
    const vec2f_t *movement);
int fx_spawn_secondary_projectile(
    const vec2f_t *pos,
    float angle,
    secondary_projectile_type_id_t type_id);
}

template <class T> inline void pu_swap(T &a, T &b)
{
    T t = a;
    a = b;
    b = t;
}

static __inline int pu_perk_level(int perk_id)
{
    return player_state_table[0].perk_counts[perk_id];
}

static __inline void player_accelerate_move_speed(player_state_t *player)
{
    if (pu_perk_level(perk_id_long_distance_runner) > 0) {
        if (player->move_speed < 2.0f) {
            player->move_speed = player->move_speed + frame_dt * 4.0f;
        }
        player->move_speed = player->move_speed + frame_dt;
        if (player->move_speed > 2.8f) {
            player->move_speed = 2.8f;
        }
    } else {
        player->move_speed = player->move_speed + frame_dt * 5.0f;
        if (player->move_speed > 2.0f) {
            player->move_speed = 2.0f;
        }
    }
}

static __inline void player_decelerate_move_speed(player_state_t *player)
{
    player->move_speed = player->move_speed - frame_dt * 15.0f;
    if (player->move_speed < 0.0f) {
        player->move_speed = 0.0f;
    }
}

static __inline void player_apply_move_speed_cap(player_state_t *player)
{
    if (player->weapon_id == 7 && player->move_speed > 0.8f) {
        player->move_speed = 0.8f;
    }
}

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

extern "C" float player_heading_approach_target(float target_heading)
{
    int player_index = current_player_index;
    while (player_state_table[player_index].heading < 0.0f) {
        player_state_table[player_index].heading += 6.2831855f;
    }
    while (player_state_table[player_index].heading > 6.2831855f) {
        player_state_table[player_index].heading -= 6.2831855f;
    }

    float direct = abs_bits(target_heading - player_state_table[player_index].heading);
    float high = player_state_table[player_index].heading;
    if (target_heading > high) {
        high = target_heading;
    }
    float low = player_state_table[player_index].heading;
    if (target_heading < low) {
        low = target_heading;
    }
    float wrapped = abs_bits((6.2831855f - high) + low);
    float amount;
    if (direct < wrapped) {
        amount = direct;
    } else {
        amount = wrapped;
    }

    if (direct > wrapped) {
        if (target_heading < player_state_table[player_index].heading) {
            player_state_table[player_index].heading += frame_dt * amount * 5.0f;
            return amount;
        } else {
            player_state_table[player_index].heading -= frame_dt * amount * 5.0f;
            return amount;
        }
    } else {
        if (target_heading > player_state_table[player_index].heading) {
            player_state_table[player_index].heading += frame_dt * amount * 5.0f;
            return amount;
        } else {
            player_state_table[player_index].heading -= frame_dt * amount * 5.0f;
            return amount;
        }
    }
}
