# music_stream_update

Samples the primary DirectSound play cursor, accounts for ring-buffer wrap, and
accumulates total and pending streamed bytes. Once pending progress exceeds one
quarter of the buffer, it consumes one quarter and requests one refill. Failed
cursor queries and exact-quarter progress do nothing.

Exact 42/42-instruction match with its native refill reference aligned.
