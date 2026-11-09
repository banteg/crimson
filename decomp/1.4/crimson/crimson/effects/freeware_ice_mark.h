// Frozen impacts use the preloaded ice texture and the shared gray half-alpha tint.
#ifndef FREEWARE_ICE_MARK_H
#define FREEWARE_ICE_MARK_H
#include "freeware_fx_queues.h"
extern "C" {
int crt_rand();
extern int freeware_ice_texture;
extern effect_color_t freeware_ice_tint;
}
#ifndef _MSC_VER
#ifndef __forceinline
#define __forceinline inline
#endif
#endif
__forceinline void freeware_shard(const vec2f_t *pos, float size) {
#ifdef CRIMSON_FREEWARE_CLIENT
    const char *texture = "icemold";
#else
    const int &texture = freeware_ice_texture;
#endif
    fx_queue_add(texture, pos, size, size, (crt_rand() % 612) * .01f, freeware_ice_tint);
}
#endif
