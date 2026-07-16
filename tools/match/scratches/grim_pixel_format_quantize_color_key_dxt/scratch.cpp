inline int grim_float_to_int(float value)
{
    return (int)value;
}

class grim_pixel_format_base_t {
public:
    virtual ~grim_pixel_format_base_t();

protected:
    unsigned int format;
    unsigned char fields_08[0x14];
    float color_key_r;
    float color_key_g;
    float color_key_b;
    float color_key_a;
    unsigned char fields_2c[0x1040];
};

class grim_pixel_format_dxt_t : public grim_pixel_format_base_t {
public:
    virtual void quantize_color_key();

private:
    float alpha_max;
    float alpha_scale;
};

void grim_pixel_format_dxt_t::quantize_color_key()
{
    if (format == 0x32545844 || format == 0x33545844) {
        alpha_max = 15.0f;
    } else {
        alpha_max = 255.0f;
    }
    alpha_scale = 1.0f / alpha_max;

    color_key_r = (float)grim_float_to_int(color_key_r * 31.0f + 0.5f) * 0.032258064f;
    color_key_g = (float)grim_float_to_int(color_key_g * 63.0f + 0.5f) * 0.015873017f;
    color_key_b = (float)grim_float_to_int(color_key_b * 31.0f + 0.5f) * 0.032258064f;
    color_key_a = (float)grim_float_to_int(color_key_a * alpha_max + 0.5f) * alpha_scale;
}
