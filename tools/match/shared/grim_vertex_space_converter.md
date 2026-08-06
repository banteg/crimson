# Grim vertex-space converter leaves

The D3DX vertex-space converter destructor installs its base vtable and frees
the allocation stored at offset `0x104c`. VC6 SP6 emits the recovered source
as the exact five-instruction, 19-byte body under the pixel-format family's
`/O1 /G6 /W3 /GR- /MD` profile.

The adjacent three-argument virtual leaf is a genuine no-op. Its member
signature explains the otherwise unusual `ret 0xc` body and matches all three
bytes exactly. Together the two leaves contribute 22 exact bytes in the
explicit `all` scope.
