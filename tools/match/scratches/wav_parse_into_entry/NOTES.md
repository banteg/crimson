# wav_parse_into_entry

Initializes a PCM `WAVEFORMATEX`, finds the first `fmt ` marker, reads channels,
sample rate, and sample width, and recomputes block alignment and byte rate. It
then finds `data`, allocates exactly the declared byte count, and copies from the
shared reader cursor. The native parser ignores the `data` search result and
performs no bounds or allocation checks; those behaviors are retained.

Exact 87/87-instruction match with all 15 native references aligned. Keeping
the parsed PCM byte count in a natural local reproduces MSVC's reuse of `EBX`
from the zero-valued format defaults through allocation and copy.

The persistent function map now uses the recovered `sfx_entry_t *` prototype
instead of its stale `void *` placeholder. Binary Ninja consequently renders
the parser as `format_tag`, `channels`, `sample_rate`, `block_align`,
`bits_per_sample`, `pcm_data`, and `pcm_bytes` accesses rather than byte
offsets. The adjacent entry lifecycle and streaming helpers use the same
canonical audio records.
