/* Compile the pinned original definitions, preserving their linkage.
 * See tools/match/CODEC-DATA-EVIDENCE-2026-09-08.md. */
#define inflate_mask zlib_inflate_mask
#include "../../../third_party/sources/zlib-1.1.3/infutil.c"
