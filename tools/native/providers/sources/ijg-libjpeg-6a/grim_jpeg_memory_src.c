/*
 * Copyright (C) 1992-1996, Thomas G. Lane.
 *
 * Derived from IJG JPEG 6a jdatasrc.c under the terms in that release's
 * README. The in-memory fields and behavior are reconstructed from grim.dll.
 */
#define JPEG_INTERNALS
#include "jinclude.h"
#include "jpeglib.h"
#include "jerror.h"

#define INPUT_BUF_SIZE 4096

typedef struct {
  struct jpeg_source_mgr pub;
  const JOCTET *source;
  int source_size;
  int source_offset;
  JOCTET *buffer;
  boolean start_of_file;
} grim_memory_source_mgr;

typedef grim_memory_source_mgr *grim_memory_src_ptr;

METHODDEF(void)
init_source(j_decompress_ptr cinfo)
{
  grim_memory_src_ptr src = (grim_memory_src_ptr)cinfo->src;

  src->start_of_file = TRUE;
}

METHODDEF(boolean)
fill_input_buffer(j_decompress_ptr cinfo)
{
  grim_memory_src_ptr src = (grim_memory_src_ptr)cinfo->src;
  int nbytes;

  if (src->source_offset < src->source_size) {
    nbytes = src->source_size - src->source_offset;
    if (nbytes > INPUT_BUF_SIZE)
      nbytes = INPUT_BUF_SIZE;

    MEMCOPY(src->buffer, src->source + src->source_offset, nbytes);
    src->source_offset += nbytes;
  } else {
    if (src->start_of_file)
      ERREXIT(cinfo, JERR_INPUT_EMPTY);

    WARNMS(cinfo, JWRN_JPEG_EOF);
    src->buffer[0] = (JOCTET)0xFF;
    src->buffer[1] = (JOCTET)JPEG_EOI;
    nbytes = 2;
  }

  src->pub.next_input_byte = src->buffer;
  src->pub.bytes_in_buffer = nbytes;
  src->start_of_file = FALSE;
  return TRUE;
}

METHODDEF(void)
skip_input_data(j_decompress_ptr cinfo, long num_bytes)
{
  grim_memory_src_ptr src = (grim_memory_src_ptr)cinfo->src;

  if (num_bytes > 0) {
    while (num_bytes > (long)src->pub.bytes_in_buffer) {
      num_bytes -= (long)src->pub.bytes_in_buffer;
      (void)fill_input_buffer(cinfo);
    }
    src->pub.next_input_byte += (size_t)num_bytes;
    src->pub.bytes_in_buffer -= (size_t)num_bytes;
  }
}

METHODDEF(void)
term_source(j_decompress_ptr cinfo)
{
}

GLOBAL(void)
grim_jpeg_memory_src(j_decompress_ptr cinfo, const JOCTET *source, int source_size)
{
  grim_memory_src_ptr src;

  if (cinfo->src == NULL) {
    cinfo->src = (struct jpeg_source_mgr *)
      (*cinfo->mem->alloc_small)((j_common_ptr)cinfo, JPOOL_PERMANENT,
                                SIZEOF(grim_memory_source_mgr));
    src = (grim_memory_src_ptr)cinfo->src;
    src->buffer = (JOCTET *)
      (*cinfo->mem->alloc_small)((j_common_ptr)cinfo, JPOOL_PERMANENT,
                                INPUT_BUF_SIZE);
  }

  src = (grim_memory_src_ptr)cinfo->src;
  src->pub.init_source = init_source;
  src->pub.fill_input_buffer = fill_input_buffer;
  src->pub.skip_input_data = skip_input_data;
  src->pub.resync_to_restart = jpeg_resync_to_restart;
  src->pub.term_source = term_source;
  src->source = source;
  src->source_size = source_size;
  src->source_offset = 0;
  src->pub.bytes_in_buffer = 0;
  src->pub.next_input_byte = NULL;
}
