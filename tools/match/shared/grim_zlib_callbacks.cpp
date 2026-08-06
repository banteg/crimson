extern "C" void *__cdecl calloc(unsigned int count, unsigned int size);
extern "C" void __cdecl free(void *allocation);

extern "C" void *grim_zcalloc(
    void *, unsigned int item_count, unsigned int item_size)
{
    return calloc(item_count, item_size);
}

extern "C" void grim_zcfree(void *, void *allocation)
{
    free(allocation);
}

struct grim_zlib_stream_t;

typedef void (__cdecl *grim_zlib_free_fn_t)(void *opaque, void *allocation);

struct grim_zlib_stream_t {
    unsigned char fields[0x24];
    grim_zlib_free_fn_t free_fn;
    void *opaque;
};

extern "C" void grim_inflate_codes_free(
    void *codes, grim_zlib_stream_t *stream)
{
    stream->free_fn(stream->opaque, codes);
}
