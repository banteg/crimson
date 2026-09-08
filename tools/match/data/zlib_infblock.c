/* Compile the pinned original definitions, preserving their linkage.
 * See tools/match/CODEC-DATA-EVIDENCE-2026-09-08.md. */
#define border zlib_inflate_border
#include "../../../third_party/sources/zlib-1.1.3/infblock.c"
