# sfx_play_exclusive

Rejects disabled audio, resolves the one-shot randomized playlist sentinel when
not under plugin control, recursively mutes every other audible track, and only
starts the selected music entry when its fade accumulator is non-positive. The
new entry receives the configured music volume and is marked unmuted.
