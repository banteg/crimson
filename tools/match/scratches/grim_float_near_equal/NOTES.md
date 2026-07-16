# Grim `float_near_equal`

Native target: `grim.dll` at `0x1000cbff` (45 bytes).

The engine uses the same nested inclusive `FLT_EPSILON` comparison as the
game executable. The nested form preserves the native x87 comparison order.
