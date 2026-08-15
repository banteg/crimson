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

#include "../../native/recovered/grim/texture/init.cpp"
#include "../../native/recovered/grim/texture/release.cpp"
#include "../../native/recovered/grim/codec/path_has_extension.cpp"

#define grim_jaz_jpeg_error_exit grim_jaz_jpeg_error_exit_decode_probe
#include "../../native/recovered/grim/codec/decode_jaz_texture.cpp"
#undef grim_jaz_jpeg_error_exit

#include "../../native/recovered/grim/texture/load_file.cpp"
#include "../../native/recovered/grim/texture/name_equals.cpp"
#include "../../native/recovered/grim/texture/find_by_name.cpp"

#define grim_texture_slots grim_texture_slots_free_probe
#include "../../native/recovered/grim/texture/find_free_slot.cpp"
#undef grim_texture_slots

#include "../../native/recovered/grim/texture/load_internal.cpp"

#undef grim_texture_format
#undef grim_preferred_texture_format

#include "../../native/recovered/grim/state/state_init.cpp"

#endif
