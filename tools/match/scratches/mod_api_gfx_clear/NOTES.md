# Native mod API graphics surface

`mod_api_init` installs the API vtable at `0x46f3e4`. Its entries are C++
virtual methods: `ECX` carries the API object and each callee pops only its
explicit arguments. The shared `mod_api_cpp_t` declaration models that native
`__thiscall` ABI rather than substituting free `__stdcall` functions that would
happen to emit the same returns when `this` is unused.

The recovered graphics leaf methods cover clear, text measurement, texture
destruction/binding, filtering, blend state, color/UV state, batch lifecycle,
individual quads, rotated quads, and raw quad batches. Every method is an exact
instruction and reference match under MSVC 6.5 `/O2`.
