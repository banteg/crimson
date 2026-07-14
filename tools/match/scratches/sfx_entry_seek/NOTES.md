# sfx_entry_seek

Streaming entries reset both the DirectSound play cursor and the underlying
Vorbis PCM cursor, then clear all native stream bookkeeping counters. Resident
entries are ignored.

The native call passes the stream object in `ECX`, proving that the Vorbis seek
wrapper is a C++ member-style call rather than an ordinary cdecl free function.

Exact 24/24-instruction match with the member-call reference aligned.
