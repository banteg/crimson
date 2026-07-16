#include <string.h>

typedef void (__stdcall *renderer_fn_t)(void);

extern "C" renderer_fn_t renderer_dispatch_table[57];
extern "C" renderer_fn_t renderer_dispatch_defaults[57];
extern "C" int renderer_backend_kind;

extern "C" void __cdecl renderer_patch_portable(renderer_fn_t *table);
extern "C" void __cdecl renderer_patch_3dnow(renderer_fn_t *table);
extern "C" void __cdecl renderer_patch_sse2(renderer_fn_t *table);
extern "C" void __cdecl renderer_patch_sse(renderer_fn_t *table);
extern "C" int __cdecl renderer_registry_read(
    unsigned long type,
    const char *name,
    unsigned char *data,
    unsigned long size);
extern "C" int __cdecl renderer_processor_feature_available(
    unsigned long feature);

extern "C" int __stdcall renderer_select_backend(int reset)
{
    if (reset == 0) {
        renderer_backend_kind = 0xffff;
        memcpy(
            renderer_dispatch_table,
            renderer_dispatch_defaults,
            sizeof(renderer_dispatch_table));
    } else if (renderer_backend_kind == 0xffff) {
        renderer_backend_kind = 0;
        memcpy(
            renderer_dispatch_table,
            renderer_dispatch_defaults,
            sizeof(renderer_dispatch_table));
        renderer_patch_portable(renderer_dispatch_table);

        if (!renderer_registry_read(
                4,
                "DisableD3DXPSGP",
                (unsigned char *)&reset,
                sizeof(reset))) {
            reset = 0;
        }

        if (reset != 1) {
            if (renderer_processor_feature_available(7)) {
                renderer_patch_3dnow(renderer_dispatch_table);
                renderer_backend_kind = 1;
            } else if (renderer_processor_feature_available(10)) {
                renderer_patch_sse2(renderer_dispatch_table);
                renderer_backend_kind = 2;
            } else if (renderer_processor_feature_available(6)) {
                renderer_patch_sse(renderer_dispatch_table);
                renderer_backend_kind = 3;
            }
        }
    }

    return renderer_backend_kind;
}
