#include "crimsonland_gameplay.h"

class effect_vertex_cpp_t {
public:
    void construct(void);

    float x;
    float y;
    float z;
    float rhw;
    unsigned int color;
    float u;
    float v;
};

typedef void (effect_vertex_cpp_t::*effect_vertex_callback_t)(void);

extern "C" void __stdcall invoke_callback_n(
    effect_vertex_cpp_t *cursor,
    int stride,
    int count,
    effect_vertex_callback_t callback);
extern "C" effect_entry_t effect_pool[0x200];

extern "C" void effect_pool_vertices_global_init(void)
{
    effect_vertex_cpp_t *vertices =
        (effect_vertex_cpp_t *)&effect_pool[0].vertices[0];
    int remaining = 0x200;

    do {
        invoke_callback_n(
            vertices,
            sizeof(effect_vertex_cpp_t),
            4,
            &effect_vertex_cpp_t::construct);
        vertices = (effect_vertex_cpp_t *)
            ((char *)vertices + sizeof(effect_entry_t));
    } while (--remaining != 0);
}
