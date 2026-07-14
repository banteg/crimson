# sfx_entry_upload_buffer

Locks the primary DirectSound buffer, restores it only for the lost-buffer
HRESULT, copies the full PCM allocation, unlocks the first region, and reports
success. Other lock failures fall through to the copy in native code; this
unsafe behavior is preserved rather than silently repaired.

Exact 57/57-instruction match with its native reference aligned.
