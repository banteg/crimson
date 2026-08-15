extern "C" char *grim_error_text;

extern "C" char *grim_get_error_text(void)
{
    return grim_error_text;
}
