# Grim pixel-format constructors

This shared source reconstructs the 37 adjacent D3DX pixel-format constructor
leaves in `grim.dll`: 30 ordinary formats, five DXT formats, and two packed-YUV
formats. Together they account for 1,008 exact bytes in the explicit `all`
matching scope.

Each constructor forwards the caller's description pointer to one of three
base constructors, installs its concrete vtable, and returns `this`. The
ordinary base also receives the recovered bit and channel counts. Keeping the
constructors in one translation unit preserves that repeated source shape
without copying it into 37 scratch files.

The exact profile is VC6 SP6 with `/O1 /G6 /W3 /GR- /MD`. Under `/O2`, the
compiler hoists the description load ahead of the base-constructor arguments
and emits one extra instruction in every ordinary constructor. The same source
is exact under `/O1` for the ordinary, DXT, and YUV representatives, making the
size-oriented profile a family-level build-property inference rather than a
single-function score choice.
