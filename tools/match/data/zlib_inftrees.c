/* Compile the pinned original definitions, preserving their linkage.
 * See tools/match/CODEC-DATA-EVIDENCE-2026-09-08.md. */
#define cplens zlib_cplens
#define cplext zlib_cplext
#define cpdist zlib_cpdist
#define cpdext zlib_cpdext
#define fixed_bl zlib_fixed_literal_bits
#define fixed_bd zlib_fixed_distance_bits
#define fixed_tl zlib_fixed_literal_tree
#define fixed_td zlib_fixed_distance_tree
#include "../../../third_party/sources/zlib-1.1.3/inftrees.c"

#include <stddef.h>
typedef char huft_record_size[(sizeof(inflate_huft) == 8) ? 1 : -1];
typedef char huft_base_offset[(offsetof(inflate_huft, base) == 4) ? 1 : -1];
