# dsound_restore_buffer

Checks for a lost DirectSound buffer, retries `Restore` until success, sleeping
10 ms only for `DSERR_BUFFERLOST`, emits the native debug line, and reports
success. Null, status-query failures, and non-lost buffers return false.

Exact 34/34-instruction match with all three native references aligned.
