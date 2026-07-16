struct vec2_t {
    float x;
    float y;
};

typedef vec2_t *(__stdcall *vec2_normalize_fn_t)(
    vec2_t *dst, const vec2_t *src);

extern "C" int __stdcall renderer_select_backend(int reset);
extern "C" vec2_normalize_fn_t vec2_normalize_impl;

extern "C" vec2_t *__stdcall vec2_normalize_dispatch_init(
    vec2_t *dst, const vec2_t *src)
{
    renderer_select_backend(1);
    return vec2_normalize_impl(dst, src);
}
