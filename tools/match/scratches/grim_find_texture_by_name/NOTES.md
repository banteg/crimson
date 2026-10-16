# grim_find_texture_by_name

## 1.9.8 bound guard

1.9.8 reads `grim_texture_slot_max_index + 1` once into a local before the
scan; 1.9.93 rereads the global on every iteration. The 1.9.8 spelling is
exact under 9044 and 66% under 1.9.93, and the rereading loop is the reverse.
`<=` bounds, a hoisted `last`, and splitting the null test from the name
comparison do not give one spelling exact in both builds.
