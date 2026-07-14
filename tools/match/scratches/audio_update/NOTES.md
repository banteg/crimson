# audio_update

Skips all work when sound is disabled, decays each positive SFX cooldown by the
per-frame delta copy, then—while audio is active—updates every loaded music
decoder and advances mute fades. Cooldowns are not clamped at zero, so one
frame may leave a small negative value.

Exact 32/32-instruction match with all ten native references aligned. Signed
loop indices are important: MSVC strength-reduces both table walks to pointers
but retains the original signed `jl` termination.
