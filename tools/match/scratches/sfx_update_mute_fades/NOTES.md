# sfx_update_mute_fades

For each loaded music entry, this keeps audible tracks playing, fades muted
tracks down at half the frame delta, and ramps unmuted tracks toward the music
volume at the full frame delta. Crossing zero stops all voices and clamps a
negative accumulator on the following check; overshooting the target volume is
clamped immediately. A non-positive configured volume directly stops the
primary buffer before the same mute/volume reconciliation.

Live instructions at `0x0043d6c7..0x0043d6e4` reload the newly computed
volume, compare it with the configured target, and take the local-volume arm
when it is less than or unordered. Expressing the clamp as the positive
`volume >= music_volume` arm preserves that native short-circuit boundary and
raises the VC6 `/O2 /GB` result from 83.76% to 84.48%. The weighted gap falls
from 60.7350 to 58.0345 bytes, with 118 target instructions, 114 candidate
instructions, and all 26 references still audited.

The remaining delta is compiler shape: native spills each newly computed
volume to the local and table, pops the x87 value, then reloads the local
before comparison; the plausible source keeps that value live.
