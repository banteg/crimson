#include "grim2d_cpp.h"

extern char *grim_error_text;

char *IGrim2D_cpp::grim_get_error_text(void)
{
    return grim_error_text;
}
