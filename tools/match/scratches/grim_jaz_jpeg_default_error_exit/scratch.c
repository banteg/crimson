#include "jinclude.h"
#include "jpeglib.h"

void error_exit(j_common_ptr cinfo)
{
  (*cinfo->err->output_message) (cinfo);
  jpeg_destroy(cinfo);
}
