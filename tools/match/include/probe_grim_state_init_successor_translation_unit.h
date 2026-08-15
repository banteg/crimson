#ifndef CRIMSON_PROBE_GRIM_STATE_INIT_SUCCESSOR_TRANSLATION_UNIT_H
#define CRIMSON_PROBE_GRIM_STATE_INIT_SUCCESSOR_TRANSLATION_UNIT_H

/*
 * Native-address-order probe for grim_state_init plus the immediately
 * following lookup-blob loader. Scratch-local identities are renamed only
 * where the two recovered files would otherwise collide.
 */
#define grim_lookup_blob_loaded grim_lookup_blob_loaded_successor_probe
#define grim_lookup_blob grim_lookup_blob_successor_probe
#define grim_lookup_blob_size grim_lookup_blob_size_successor_probe
#include "../scratches/grim_state_init/scratch.cpp"
#undef grim_lookup_blob_loaded
#undef grim_lookup_blob
#undef grim_lookup_blob_size
#include "../scratches/grim_lookup_blob_load/scratch.cpp"

#endif
