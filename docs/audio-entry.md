---
tags:
  - status-draft
---

# Audio entry struct (sfx_entry_t / music_entry_t)

SFX and music tracks share the same 0x84-byte entry layout. The runtime uses
this struct for both `sfx_entry_table` and `music_entry_table`.

## Layout (audio_entry_t)

Offsets are relative to the entry base and match the initialization logic in
`wav_parse_into_entry`, `sfx_entry_load_ogg`, and `music_entry_load_ogg`.

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0x00 | u16 | format_tag | Set to `1` (PCM) for WAV and OGG decode. |
| 0x02 | u16 | channels | Written from WAV header / Vorbis info. |
| 0x04 | u32 | sample_rate | `nSamplesPerSec`. |
| 0x08 | u32 | avg_bytes_per_sec | `nAvgBytesPerSec`. |
| 0x0c | u16 | block_align | `nBlockAlign`. |
| 0x0e | u16 | bits_per_sample | `wBitsPerSample` (usually 16). |
| 0x10 | u16 | cb_size | Extra size (usually 0). |
| 0x12 | u16 | _pad | Alignment. |
| 0x14 | ptr | pcm_data | Heap buffer holding decoded PCM. |
| 0x18 | u32 | pcm_bytes | Size of `pcm_data` / stream buffer in bytes. |
| 0x1c | u32 | stream_cursor | Current cursor used by streaming refill logic. |
| 0x20 | f32 | volume | Cached volume scalar. |
| 0x24 | ptr[16] | buffers | DirectSound buffer pointers (primary + 15 duplicates). |
| 0x64 | u8[16] | buffer_in_use | Voice-active flags set during playback. |
| 0x74 | ptr | vorbis_stream | Non-null for streaming music entries. |
| 0x78 | u32 | stream_fill_bytes | Bytes remaining in the current stream chunk. |
| 0x7c | u32 | stream_total_bytes | Accumulated bytes written to the stream. |
| 0x80 | u32 | stream_cursor_bytes | Cursor used to trigger refill in `music_stream_update`. |

## Notes

- Static/one-shot SFX entries leave `vorbis_stream` null and use the 16 voice
  buffers at `0x24` for overlapping playback.
- Music tracks set `vorbis_stream` and use a single streaming buffer at `0x24`.
- The entry size is 0x84 bytes; table strides for `sfx_entry_table` and
  `music_entry_table` use this size.
