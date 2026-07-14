# sfx_entry_create_buffers

Creates one globally focused DirectSound buffer with volume, pan, and frequency
controls, duplicates it into all 16 resident-sample voices, uploads PCM, and
resets every voice to free, stopped, and position zero. Duplicate failures
emit the native debug line and leave prior allocations untouched.

Exact 91/91-instruction match with all nine native references aligned. The
descriptor's zero GUID is labeled as `GUID_NULL`, the DirectSound 8 default 3D
algorithm value copied by the original build.
