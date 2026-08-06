void __cdecl operator delete(void *allocation);

struct grim_vertex_space_converter_t {
    virtual ~grim_vertex_space_converter_t();

    unsigned char fields[0x104c];
};

struct grim_pixel_format_yuv_t : grim_vertex_space_converter_t {
    virtual ~grim_pixel_format_yuv_t();
    void flush_cache();

    unsigned char fields[0x1c];
    void *allocation;
};

grim_pixel_format_yuv_t::~grim_pixel_format_yuv_t()
{
    flush_cache();
    if (allocation != 0) {
        operator delete(allocation);
    }
}
