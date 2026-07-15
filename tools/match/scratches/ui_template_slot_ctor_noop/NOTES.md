# ui_template_slot_ctor_noop

Native target: `crimsonland.exe` at `0x00417a90` (3 bytes).

The callback iterator invokes this constructor across 0x1c-byte vertex-like UI
template slots. The class owns no resources and supplies no defaults, so the
natural VC6 constructor only returns `this`: both native instructions match,
with no static references.
