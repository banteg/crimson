#ifndef CRIMSON_PROBE_GRIM_STATE_INIT_TRANSLATION_UNIT_H
#define CRIMSON_PROBE_GRIM_STATE_INIT_TRANSLATION_UNIT_H

#define grim_texture_format grim_texture_format_predecessor_probe
#define grim_preferred_texture_format \
    grim_preferred_texture_format_predecessor_probe
#include "../scratches/grim_texture_name_equals/scratch.cpp"
#include "../scratches/grim_find_texture_by_name/scratch.cpp"
#define grim_texture_slots grim_texture_slots_free_probe
#include "../scratches/grim_find_free_texture_slot/scratch.cpp"
#undef grim_texture_slots
#include "../scratches/grim_load_texture_internal/scratch.cpp"
#undef grim_texture_format
#undef grim_preferred_texture_format
#include "../scratches/grim_state_init/scratch.cpp"

#endif
