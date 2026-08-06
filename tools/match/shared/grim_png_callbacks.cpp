extern "C" __declspec(noreturn) void __cdecl longjmp(
    void *jump_buffer, int value);
extern "C" void __cdecl free(void *allocation);
extern "C" void __cdecl png_free(void *png, void *allocation);
extern "C" void *__cdecl memset(void *destination, int value, unsigned int size);
extern "C" unsigned long __cdecl grim_png_crc32(
    unsigned long crc, const unsigned char *data, unsigned int length);

struct grim_png_t;

typedef void (__cdecl *grim_png_error_fn_t)(
    grim_png_t *png, const char *message);
typedef void (__cdecl *grim_png_rw_fn_t)(
    grim_png_t *png, unsigned char *data, unsigned int length);

struct grim_png_t {
    unsigned char fields_00[0x40];
    grim_png_error_fn_t error_fn;
    grim_png_error_fn_t warning_fn;
    void *error_ptr;
    grim_png_rw_fn_t write_data_fn;
    grim_png_rw_fn_t read_data_fn;
    void *io_ptr;
    unsigned char fields_58[4];
    unsigned int flags;
    unsigned char fields_60[0xa0];
    unsigned long crc;
    unsigned char fields_104[8];
    unsigned int chunk_name;
    unsigned char fields_110[0x10];
    unsigned int flush_distance;
};

extern "C" void grim_png_error(grim_png_t *png, const char *message);
extern "C" void grim_png_warning(grim_png_t *png, const char *message);
extern "C" unsigned char grim_png_signature[8];
extern "C" int __cdecl memcmp(
    const void *left, const void *right, unsigned int length);

extern "C" __declspec(noreturn) void grim_png_error_longjmp(
    void *jump_buffer, const char *)
{
    longjmp(jump_buffer, 1);
}

extern "C" void grim_png_zfree(void *png, void *allocation)
{
    png_free(png, allocation);
}

extern "C" void grim_png_destroy_struct(void *allocation)
{
    if (allocation == 0) {
        return;
    }
    free(allocation);
}

extern "C" void grim_png_info_destroy(void *, void *info)
{
    memset(info, 0, 0x40);
}

extern "C" void grim_png_set_error_fn(
    grim_png_t *png,
    void *error_ptr,
    grim_png_error_fn_t error_fn,
    grim_png_error_fn_t warning_fn)
{
    png->error_ptr = error_ptr;
    png->error_fn = error_fn;
    png->warning_fn = warning_fn;
}

extern "C" void grim_png_read_data(
    grim_png_t *png, unsigned char *data, unsigned int length)
{
    if (png->read_data_fn != 0) {
        png->read_data_fn(png, data, length);
    } else {
        grim_png_error(png, "Call to NULL read function");
    }
}

extern "C" void grim_png_set_read_fn(
    grim_png_t *png, void *io_ptr, grim_png_rw_fn_t read_data_fn)
{
    png->io_ptr = io_ptr;
    png->read_data_fn = read_data_fn;

    if (png->write_data_fn != 0) {
        png->write_data_fn = 0;
        grim_png_warning(
            png,
            "It's an error to set both read_data_fn and write_data_fn in the ");
        grim_png_warning(
            png,
            "same structure.  Resetting write_data_fn to NULL.");
    }

    png->flush_distance = 0;
}

extern "C" int grim_png_sig_cmp(
    unsigned char *signature, unsigned int start, unsigned int length)
{
    if (length > 8) {
        length = 8;
    } else if (length < 1) {
        return 0;
    }

    if (start > 7) {
        return 0;
    }
    if (start + length > 8) {
        length = 8 - start;
    }

    return memcmp(
        signature + start,
        grim_png_signature + start,
        length);
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
