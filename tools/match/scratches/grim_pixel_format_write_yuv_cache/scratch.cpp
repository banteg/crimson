#include <string.h>

struct grim_yuv_cache_entry_t {
    float channels[4];
};

class grim_pixel_format_t {
public:
    virtual ~grim_pixel_format_t();
    virtual void read_pixel(unsigned int x, unsigned int y, float *pixels);
    virtual void write_pixel(unsigned int x, unsigned int y, float *pixels);
    virtual void quantize_color_key();

protected:
    float *convert_vertex_space(float *source);
    void apply_color_key(float *pixels);

    unsigned int format;
    unsigned int coordinate_mode;
    unsigned int has_pixel_buffer;
    unsigned int color_key_enabled;
    unsigned int field_14;
    unsigned char *pixel_buffer;
    float color_key[4];
    float *dither_pattern;
    unsigned char palette[0x1000];
    unsigned int left;
    unsigned int top;
    unsigned int right;
    unsigned int bottom;
    unsigned int depth_first;
    unsigned int depth_last;
    unsigned int conversion_mode;
    float *conversion_source;
    unsigned int bytes_per_row;
    unsigned int bytes_per_pixel;
    unsigned int width;
    unsigned int height;
    unsigned int depth;
    unsigned int row_pitch;
    unsigned int slice_pitch;
};

class grim_pixel_format_yuv_t : public grim_pixel_format_t {
public:
    virtual void read_pixel(unsigned int x, unsigned int y, float *pixels);
    virtual void write_pixel(unsigned int x, unsigned int y, float *pixels);

protected:
    int load_yuv_cache(unsigned int x, unsigned int y, int load_from_surface);

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

void grim_pixel_format_yuv_t::write_pixel(
    unsigned int x,
    unsigned int y,
    float *pixels)
{
    if (conversion_mode != 0) {
        pixels = convert_vertex_space(pixels);
    }

    x += top;
    y += depth_first;
    if (load_yuv_cache(x, y, cache_width != width) >= 0) {
        memcpy(cache + (left - aligned_left), pixels, width * sizeof(*cache));
        dirty = 1;
    }
}
