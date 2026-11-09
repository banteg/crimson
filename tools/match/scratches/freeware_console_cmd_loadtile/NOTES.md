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

The ordinary 1.4.0 scratch compiles with the stock VC6 SP5 headers and /GX.
It scores 81.14% (331 candidate instructions versus 337 native). Of the 68
aligned references, 67 agree. At `0x0041ffdd`, native code calls the vector's
`_Ufill` helper (`0x00421940`). VC6 expands the first fill inline in this
scratch and calls `std::_Construct` (`0x00421970`) directly. VC6 also calls
`size()` after deallocation where the native code computes the pointer
difference inline. These changes affect register allocation and branch offsets.

The native vector insertion consistently calls its range helpers:
`_Ucopy` at `0x00421910`, `_Ufill` at `0x00421940` and `_Destroy` at
`0x004216f0`. A separate compiler experiment exposed those three members as
out-of-line callees and force-inlined the original `size()` body. With the
same command source it reproduced all 1,015 bytes and all 73 references.
The published scratch uses the stock headers to keep its WIP score reproducible.
