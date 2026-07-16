class grim_pixel_format_a2b10g10r10_t {
public:
    virtual ~grim_pixel_format_a2b10g10r10_t();
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
};

void grim_pixel_format_a2b10g10r10_t::read_pixel(
    unsigned int row,
    unsigned int depth,
    float *pixels)
{
    unsigned int *source =
        (unsigned int *)(pixel_buffer + row_offset * row + depth_offset * depth);
    unsigned int *end = source + width;
    const float scale = 1.0f / 1023.0f;
    while (source < end) {
        pixels[0] = (float)(*source & 0x3ff) * scale;
        pixels[1] = (float)((*source >> 10) & 0x3ff) * scale;
        pixels[2] = (float)((*source >> 20) & 0x3ff) * scale;
        pixels[3] = (float)(*source++ >> 30) * (1.0f / 3.0f);
        pixels += 4;
    }

    if (color_key_enabled != 0) {
        apply_color_key(pixels - width * 4);
    }
}
