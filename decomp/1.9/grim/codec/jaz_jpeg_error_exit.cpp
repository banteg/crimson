#include <setjmp.h>
#include <stdio.h>

#include "jpeglib.h"

struct GrimJazJpegError {
    jpeg_error_mgr base;
    jmp_buf jump_buffer;
};

extern "C" void grim_jaz_jpeg_error_exit(j_common_ptr context)
{
    char message[JMSG_LENGTH_MAX];
    GrimJazJpegError *error = (GrimJazJpegError *)context->err;
    (*context->err->format_message)(context, message);
    longjmp(error->jump_buffer, 1);
}
