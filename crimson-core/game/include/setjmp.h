#pragma once
// wasm32 has no setjmp without the exception-handling proposal. The image
// decoders jump back only on a corrupt image; that stops the module instead.
typedef int jmp_buf[1];
#define setjmp(env) ((void)(env), 0)
#ifdef __cplusplus
extern "C"
#endif
    [[noreturn]] void platform_longjmp(void);
#define longjmp(env, value) ((void)(env), (void)(value), platform_longjmp())
