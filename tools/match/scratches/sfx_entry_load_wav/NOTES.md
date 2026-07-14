# sfx_entry_load_wav

Reads a packed or standalone WAV resource into temporary storage, parses it into
the entry, frees the temporary bytes on both parse outcomes, then creates the 16
resident DirectSound voices. The return value is normalized to boolean.

Exact 44/44-instruction match with all five native references aligned.
