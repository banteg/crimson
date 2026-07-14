# sfx_entry_stop

Streaming entries stop only their primary buffer. Resident samples stop every
allocated voice in the 16-buffer array. Null entries and null buffers are safe.

Exact 29/29-instruction match.
