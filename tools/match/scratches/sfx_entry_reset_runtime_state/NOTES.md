# sfx_entry_reset_runtime_state

This member-style initializer clears the stream object and counters, PCM owner
and lengths, cached volume, and all 16 DirectSound buffer pointers. It leaves
the 16-byte `buffer_in_use` array untouched. The pointer arrives in `ECX` and is
returned in `EAX`, consistent with a C++ initializer/constructor helper.

Exact 19/19-instruction match. The recovered decorated member alias is recorded
in the native name map.
