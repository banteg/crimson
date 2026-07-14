# sfx_mute_all

When audio and music are enabled, clears the randomized-playlist latch, walks
all 128 ids, and recursively mutes every other currently audible id before
marking the requested id muted. The recursion terminates through the flag
written by each child after its own scan; the resulting quadratic traversal is
native behavior.

Exact 31/31-instruction match with all six native references aligned. The
matcher now recognizes the COFF `REL32` self-call as native local label `L0`, so
the recursive call is verified rather than hidden behind an address mask.
