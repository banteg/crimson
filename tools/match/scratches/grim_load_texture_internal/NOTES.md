# grim_load_texture_internal

The helper rejects an exhausted table and duplicate names, constructs a
`GrimTexture`, delegates file decoding/loading to its member method, then
publishes the owner into the selected handle. A failed load records the D3D
error and deletes the temporary owner. The helper has C++ linkage: with the
otherwise identical `extern "C"` declaration VC6 omitted the constructor
unwind graph, while the decorated free function reproduces the native frame,
state slot, cleanup funclet, and all 80 instructions exactly. Writing the
failure branch first also reproduces the native success tail.
