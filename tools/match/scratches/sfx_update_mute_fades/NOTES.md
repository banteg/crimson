# sfx_update_mute_fades

For each loaded music entry, this keeps audible tracks playing, fades muted
tracks down at half the frame delta, and ramps unmuted tracks toward the music
volume at the full frame delta. Crossing zero stops all voices and clamps a
negative accumulator on the following check; overshooting the target volume is
clamped immediately. A non-positive configured volume directly stops the
primary buffer before the same mute/volume reconciliation.

Current VC6 `/O2 /GB` result: 83.76% (118 target instructions, 116 candidate,
26 audited references). The remaining delta is compiler shape: native spills
each newly computed volume to the local and table, pops the x87 value, then
reloads the local before comparison; the plausible source keeps that value live.
The target-volume selection also uses the opposite equivalent branch layout.
