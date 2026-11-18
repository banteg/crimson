// The 1.4.0 queues keep one writable slot beyond their capped draw counts.
#ifndef FREEWARE_FX_QUEUES_H
#define FREEWARE_FX_QUEUES_H
#include "crimsonland_types.h"
#ifdef CRIMSON_FREEWARE_CLIENT
#include "game.h"
extern freeware::Game *freeware_frame_game;
typedef const char *FreewareFxTexture;
#define FX_STORE(native, member) (freeware_frame_game->fx.member)
#else
typedef int FreewareFxTexture;
#define FX_STORE(native, member) (native)
extern "C" {
extern fx_queue_entry_t fx_queue[];
extern int fx_queue_count, freeware_blood_count, freeware_shell_count, freeware_corpse_count;
extern vec2f_t freeware_blood_positions[], freeware_shell_positions[], freeware_corpse_positions[];
extern effect_color_t freeware_corpse_colors[];
extern float freeware_corpse_angles[], freeware_corpse_sizes[];
extern int freeware_corpse_species[];
extern unsigned char freeware_shell_marks;
}
#endif
extern "C" {
void fx_queue_add(FreewareFxTexture, const vec2f_t *, float, float, float, effect_color_t);
void fx_queue_add_random(const vec2f_t *);
void fx_queue_add_shell(const vec2f_t *);
void fx_queue_add_rotated(const vec2f_t *, const effect_color_t *, float, float, int);
}
#endif
