class grim_yuv_cache_entry_t {
public:
    grim_yuv_cache_entry_t();

private:
    float channels[4];
};

class grim_pixel_format_base_t {
public:
    virtual void placeholder(void);
    virtual ~grim_pixel_format_base_t();

    grim_pixel_format_base_t(
        unsigned int *desc,
        unsigned int bits_per_pixel,
        unsigned int coord_mode);

protected:
    unsigned int format;
    unsigned char fields_08[0x1028];
    unsigned int left;
    unsigned int top;
    unsigned int right;
    unsigned int bottom;
    unsigned int depth_first;
    unsigned int depth_last;
    unsigned char fields_1048[0x24];
};

class grim_pixel_format_yuv_t : public grim_pixel_format_base_t {
public:
    virtual void placeholder(void);

    grim_pixel_format_yuv_t(unsigned int *desc);

private:
    grim_yuv_cache_entry_t *cache;
    unsigned int aligned_left;
    unsigned int cached_x;
    unsigned int aligned_right;
    unsigned int cached_y;
    unsigned int cache_start;
    unsigned int cache_end;
    unsigned int cache_width;
    unsigned int dirty;
    unsigned int cache_enabled;
    unsigned int chroma_offset;
    unsigned int luma_offset;
};

grim_pixel_format_yuv_t::grim_pixel_format_yuv_t(unsigned int *desc)
    : grim_pixel_format_base_t(desc, 0, 1)
{
    aligned_left = left & ~1u;
    aligned_right = (right + 1) & ~1u;
    cached_x = 0;
    cache_start = 0;
    cached_y = 0;
    cache_end = 0;
    cache_width = aligned_right - aligned_left;
    dirty = 0;
    cache_enabled = 1;

    cache = new grim_yuv_cache_entry_t[cache_width];
    if (cache == 0) {
        cache_enabled = 0;
    }

    if (desc[1] == 0x59565955) {
        chroma_offset = 8;
        luma_offset = 0;
    } else {
        chroma_offset = 0;
        luma_offset = 8;
    }
}
