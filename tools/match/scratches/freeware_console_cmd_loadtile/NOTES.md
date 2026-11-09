# Freeware loadtile command

In Crimsonland 1.4.0, the console registers this callback at `0x0041fd30`.
The 1,015-byte body ends at `0x00420127`. It opens the PAQ named by Grim
configuration slot 16, skips its four-byte signature and reads each entry's
name, size and 18-byte TGA header. It compares the requested name
case-sensitively. A match loads the texture, creates a brush with the header's
width and height, and appends it to the editor's brush collection. The file
open and entry lookup failures have distinct messages. The constructor sets
rotation and flags to zero and all four color channels to one.

## VC6 inlining

The stock 1.4.0 compiler and headers with `/GX` reproduce all 1,015 bytes,
337 instructions and 73 positional references. The brush initializer passes
its color member by reference and sets alpha, blue, green and red separately.
The same constructor reproduces the 1.3.0 startup code.

Treating the setter as a brush member with a chained assignment left 41
units in VC6's inline budget where `vector::size()` requires 42. The original
inlines that pointer difference after deallocation at `0x0042001b`. It calls
`_Ucopy`, `_Ufill` and `_Destroy` out of line.
