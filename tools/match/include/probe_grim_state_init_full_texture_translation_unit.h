#ifndef CRIMSON_PROBE_GRIM_STATE_INIT_FULL_TEXTURE_TRANSLATION_UNIT_H
#define CRIMSON_PROBE_GRIM_STATE_INIT_FULL_TEXTURE_TRANSLATION_UNIT_H

/*
 * Native-address-order probe for the complete texture island preceding
 * grim_state_init.  Scratch-local declarations are renamed only where two
 * independently recovered files would otherwise collide in one replay TU.
 */
#define grim_texture_format grim_texture_format_full_texture_probe
#define grim_preferred_texture_format \
    grim_preferred_texture_format_full_texture_probe

#include "../scratches/grim_texture_init/scratch.cpp"
#include "../scratches/grim_texture_release/scratch.cpp"
#include "../scratches/grim_path_has_extension/scratch.cpp"

#define grim_jaz_jpeg_error_exit grim_jaz_jpeg_error_exit_decode_probe
#include "../scratches/grim_decode_jaz_texture/scratch.cpp"
#undef grim_jaz_jpeg_error_exit

#include "../scratches/grim_texture_load_file/scratch.cpp"
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
