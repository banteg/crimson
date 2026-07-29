/*
 * Copyright (C) 1994-1996, Thomas G. Lane.
 * This file is derived from IJG JPEG 6a jdapimin.c and remains subject to the
 * conditions in that release's README.
 *
 * Isolated verbatim body from IJG JPEG 6a jdapimin.c.
 *
 * Keeping this public wrapper separate lets the native provider resolve the
 * byte-exact JAZ entry point without also claiming the neighboring entry
 * points whose reference bodies differ.
 */
#define JPEG_INTERNALS
#include "jinclude.h"
#include "jpeglib.h"

GLOBAL(void)
jpeg_destroy_decompress(j_decompress_ptr cinfo)
{
  jpeg_destroy((j_common_ptr)cinfo);
}
