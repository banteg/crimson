# grim_get_frame_dt

## Plausibility pass (2026-09-27)

The function is defined as the `IGrim2D_cpp` vtable method, like its siblings, instead of an `extern "C"` function. The vtable initializer in `tools/native/data_definitions/grim.dll.json` names the method symbol. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md).
