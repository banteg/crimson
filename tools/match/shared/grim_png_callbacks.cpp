extern "C" __declspec(noreturn) void __cdecl longjmp(
    void *jump_buffer, int value);
extern "C" void __cdecl free(void *allocation);
extern "C" void __cdecl png_free(void *png, void *allocation);
extern "C" void *__cdecl memset(void *destination, int value, unsigned int size);
extern "C" unsigned long __cdecl grim_png_crc32(
    unsigned long crc, const unsigned char *data, unsigned int length);

struct grim_png_t;

typedef void (__cdecl *grim_png_warning_fn_t)(
    grim_png_t *png, const char *message);

struct grim_png_t {
    unsigned char fields_00[0x44];
    grim_png_warning_fn_t warning_fn;
    unsigned char fields_48[0x14];
    unsigned int flags;
    unsigned char fields_60[0xa0];
    unsigned long crc;
    unsigned char fields_104[8];
    unsigned int chunk_name;
};

extern "C" __declspec(noreturn) void grim_png_error_longjmp(
    void *jump_buffer, const char *)
{
    longjmp(jump_buffer, 1);
}

extern "C" void grim_png_free_thunk(void *png, void *allocation)
{
    png_free(png, allocation);
}

extern "C" void grim_png_free_ptr(void *allocation)
{
    if (allocation == 0) {
        return;
    }
    free(allocation);
}

extern "C" void grim_png_info_clear(void *, void *info)
{
    memset(info, 0, 0x40);
}

extern "C" void grim_png_warning(grim_png_t *png, const char *message)
{
    if (png->warning_fn != 0) {
        png->warning_fn(png, message);
    }
}

extern "C" void grim_png_reset_crc(grim_png_t *png)
{
    png->crc = grim_png_crc32(0, 0, 0);
}

extern "C" void grim_png_calculate_crc(
    grim_png_t *png, const unsigned char *data, unsigned int length)
{
    if ((png->chunk_name & 0x20) != 0) {
        if ((png->flags & 0x300) != 0x300) {
            goto update_crc;
        }
        return;
    }
    if ((png->flags & 0x800) != 0) {
        return;
    }

update_crc:
    png->crc = grim_png_crc32(png->crc, data, length);
}
