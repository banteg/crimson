# grim_is_texture_format_supported

`grim_is_texture_format_supported` at `0x100047f0` forwards the active D3D8
configuration to `IDirect3D8::CheckDeviceFormat`:

- selected adapter index;
- selected HAL/REF device type;
- current adapter/texture format;
- usage `0`;
- resource type `D3DRTYPE_TEXTURE`;
- candidate texture format.

It converts the HRESULT sign test directly to a byte-sized C++ `bool`. The
recovered expression matches all 19 native instructions and all four global
references under MSVC 6.5 `/O2 /GB`.

Binary Ninja's inferred `int32_t` return prototype is contradicted by the
terminal `setge cl; mov al, cl`; a previewed `bool` correction simplified HLIL
as expected, although the live analyzer rejected persistence, so the durable
ABI correction lives in the source map and scratch rather than being forced.
