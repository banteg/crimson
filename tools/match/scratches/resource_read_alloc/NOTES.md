# resource_read_alloc

Opens a packed or standalone resource, allocates exactly its reported byte
count, reads one full item, closes the shared stream, and returns the owned
buffer and size to the caller. The native code does not add a terminator or
check the allocation/read results.

Keeping a natural local copy of the shared `FILE *` live across allocation
reproduces MSVC's `EBX` preservation. The result is an exact 33/33-instruction
match with all five native references aligned.
