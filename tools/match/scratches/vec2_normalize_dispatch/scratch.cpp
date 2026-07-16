struct vec2_t {
    float x;
    float y;
};

typedef vec2_t *(__stdcall *vec2_normalize_fn_t)(
    vec2_t *dst, const vec2_t *src);

extern "C" vec2_normalize_fn_t vec2_normalize_impl;

extern "C" vec2_t *__stdcall vec2_normalize_dispatch(
    vec2_t *dst, const vec2_t *src)
{
    return vec2_normalize_impl(dst, src);
}
