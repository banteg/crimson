# `grim_pixel_format_scalar_deleting_destroy_dxt`

Native target: `grim.dll` at `0x1001b472` (28 bytes).

This is VC6's scalar deleting wrapper shared by the DXT1 through DXT5 format
classes. It invokes the regular DXT destructor and conditionally releases
`this` from the deleting flag.
