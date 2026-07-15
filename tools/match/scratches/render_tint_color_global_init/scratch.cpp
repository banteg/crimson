struct render_tint_color_t {
    float r;
    float g;
    float b;
    float a;
};

extern "C" render_tint_color_t render_tint_color;

extern "C" void render_tint_color_global_init(void)
{
    render_tint_color.r = 0.58431375f;
    render_tint_color.g = 0.686274529f;
    render_tint_color.b = 0.776470602f;
    render_tint_color.a = 0.699999988f;
}
