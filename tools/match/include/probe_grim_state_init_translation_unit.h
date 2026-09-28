#ifndef CRIMSON_PROBE_GRIM_STATE_INIT_TRANSLATION_UNIT_H
#define CRIMSON_PROBE_GRIM_STATE_INIT_TRANSLATION_UNIT_H

#define grim_texture_format grim_texture_format_predecessor_probe
#define grim_preferred_texture_format \
    grim_preferred_texture_format_predecessor_probe
#include "../../../decomp/1.9/grim/texture/name_equals.cpp"
#include "../../../decomp/1.9/grim/texture/find_by_name.cpp"
#define grim_texture_slots grim_texture_slots_free_probe
#include "../../../decomp/1.9/grim/texture/find_free_slot.cpp"
#undef grim_texture_slots
#include "../../../decomp/1.9/grim/texture/load_internal.cpp"
#undef grim_texture_format
#undef grim_preferred_texture_format
#include "../../../decomp/1.9/grim/state/state_init.cpp"

#endif
