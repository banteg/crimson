class grim_pixel_format_r16_t {
public:
    virtual ~grim_pixel_format_r16_t();
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
    unsigned char palette[0x1000];
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
    unsigned int height;
    unsigned int depth_count;
    unsigned int row_size;
    unsigned int bytes_per_pixel;
};

void grim_pixel_format_r16_t::read_pixel(
    unsigned int row,
    unsigned int depth,
    float *pixels)
{
    unsigned short *source =
        (unsigned short *)(pixel_buffer + row_offset * row + depth_offset * depth);
    unsigned short *end =
        (unsigned short *)((unsigned char *)source + row_size);
    const float scale = 1.0f / 65535.0f;
    while (source < end) {
        pixels[0] = (float)source[2] * scale;
        pixels[1] = (float)source[1] * scale;
        pixels[2] = (float)source[0] * scale;
        source += 3;
        pixels[3] = 1.0f;
        pixels += 4;
    }

    if (color_key_enabled != 0) {
        apply_color_key(pixels - width * 4);
    }
}
