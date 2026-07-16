class grim_pixel_format_a1r5g5b5_t {
public:
    virtual ~grim_pixel_format_a1r5g5b5_t();
    virtual void read_pixel(unsigned int row, unsigned int depth, float *pixels);
    virtual void write_pixel(unsigned int row, unsigned int depth, float *pixels);
    virtual void quantize_color_key();
protected:
    void apply_color_key(float *pixels);
    unsigned int format, coordinate_mode, has_pixel_buffer, color_key_enabled, field_14;
    unsigned char *pixel_buffer;
    float color_key[4];
    float *dither_pattern;
    unsigned char palette[0x1000];
    unsigned int left, top, right, bottom, depth_first, depth_last, conversion_mode;
    float *conversion_source;
    unsigned int row_offset, depth_offset, width;
};

void grim_pixel_format_a1r5g5b5_t::read_pixel(
    unsigned int row, unsigned int depth, float *pixels)
{
    unsigned short *source = (unsigned short *)(pixel_buffer + row_offset * row + depth_offset * depth);
    unsigned short *end = source + width;
    const float scale = 1.0f / 31.0f;
    while (source < end) {
        pixels[0] = (float)((*source >> 10) & 0x1f) * scale;
        pixels[1] = (float)((*source >> 5) & 0x1f) * scale;
        pixels[2] = (float)(*source & 0x1f) * scale;
        pixels[3] = (float)(*source++ >> 15);
        pixels += 4;
    }
    if (color_key_enabled != 0) {
        apply_color_key(pixels - width * 4);
    }
}
