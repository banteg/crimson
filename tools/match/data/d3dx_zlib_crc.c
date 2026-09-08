/* Compile the pinned original definitions, preserving their linkage.
 * See tools/match/CODEC-DATA-EVIDENCE-2026-09-08.md. */
#define crc_table d3dx_zlib_crc_table
#include "../../../third_party/sources/zlib-1.1.3/crc32.c"
