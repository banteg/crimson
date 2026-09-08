/* Compile the pinned original definitions, preserving their linkage.
 * See tools/match/CODEC-DATA-EVIDENCE-2026-09-08.md. */
#define extra_lbits zlib_extra_literal_bits
#define extra_dbits zlib_extra_distance_bits
#define bl_order zlib_bit_length_order
#define static_ltree zlib_static_literal_tree
#define static_dtree zlib_static_distance_tree
#define _dist_code zlib_distance_code
#define _length_code zlib_length_code
#define base_length zlib_base_length
#define base_dist zlib_base_distance
#include "../../../third_party/sources/zlib-1.1.3/trees.c"

#include <stddef.h>
typedef char tree_record_size[(sizeof(ct_data) == 4) ? 1 : -1];
typedef char tree_length_offset[(offsetof(ct_data, dl) == 2) ? 1 : -1];
