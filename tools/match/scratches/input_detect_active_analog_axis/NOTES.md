# input_detect_active_analog_axis

Native target: `crimsonland.exe` at `0x448b50` (377 bytes).

The helper probes the six analog configuration channels in this exact order:
`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and `0x155`. It clears each
sample's IEEE-754 sign bit and returns the first channel whose magnitude is
greater than `0.5f`. If no channel is active, it flushes pending input through
`IGrim2D_cpp::grim_flush_input()` and returns zero.

The recovered source preserves all calls, channel IDs, comparisons, early
returns, and the no-hit flush. It remains a work in progress: MSVC 6.5 `/O2`
hoists the repeated `0x7fffffff` mask into `ESI`, while the native object emits
the immediate mask at every test. `/O1` is decisively less plausible because it
adds a frame, registerizes channel IDs, changes x87 condition lowering, and
shares the return paths. No dummy dependencies or volatile fakematching are
used to suppress the honest optimizer difference.
