#include <string.h>

class grim_pixel_format_a8p8_t {
public:
    virtual ~grim_pixel_format_a8p8_t();
    virtual void read_pixel(unsigned int row, unsigned int depth, float *pixels);
    virtual void write_pixel(unsigned int row, unsigned int depth, float *pixels);
    virtual void quantize_color_key();

protected:
    void apply_color_key(float *pixels);

    unsigned int format;
    unsigned int coordinate_mode;
    unsigned int has_pixel_buffer;
    unsigned int color_key_enabled;
    unsigned int field_14;
    unsigned char *pixel_buffer;
    float color_key[4];
    float *dither_pattern;
    float palette[256][4];
    unsigned int left;
    unsigned int top;
    unsigned int right;
    unsigned int bottom;
    unsigned int depth_first;
    unsigned int depth_last;
    unsigned int conversion_mode;
    float *conversion_source;
    unsigned int row_offset;
    unsigned int depth_offset;
    unsigned int width;
};

void grim_pixel_format_a8p8_t::read_pixel(
    unsigned int row,
    unsigned int depth,
    float *pixels)
{
    unsigned short *source = (unsigned short *)(pixel_buffer + row_offset * row + depth_offset * depth);
    unsigned short *end = source + width;
    while (source < end) {
        memcpy(pixels, palette[*source & 0xff], sizeof(palette[0]));
        pixels[3] = (float)(*source >> 8) * (1.0f / 255.0f);
        ++source;
        pixels += 4;
    }

    if (color_key_enabled != 0) {
        apply_color_key(pixels - width * 4);
    }
}
