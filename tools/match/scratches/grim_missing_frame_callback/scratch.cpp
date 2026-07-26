extern char *grim_error_text;
extern const char grim_missing_frame_error_text[];

extern "C" bool grim_missing_frame_callback(void)
{
    grim_error_text = (char *)grim_missing_frame_error_text;
    return false;
}
