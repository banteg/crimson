# `quest_build_alien_squads`

Native target: `crimsonland.exe` at `0x00435ea0` (507 bytes).

Live Binary Ninja evidence recovers eight fixed template-`0x12` entries, all
with count 1 and heading left untouched:

- `(-256, 256)` at trigger 1500;
- `(-256, 768)` at trigger 2500;
- `(768, -256)` at trigger 5500;
- `(768, 1280)` at trigger 8500;
- `(1280, 1280)` at trigger 14500;
- `(1280, 768)` at trigger 18500;
- `(-256, 256)` at trigger 25000;
- `(-256, 768)` at trigger 30000.

The remaining 52 entries are 26 paired waves. Starting at trigger 36200 and
advancing by 1800 while the trigger is below 83000, each pair adds a
template-`0x26` spawn at `(-64, -64)` with trigger minus 400, followed by one
at the native fixed corner `(1088, 1088)` with the unadjusted trigger. This is
not derived from the terrain dimensions; recovering the hardcoded corner also
revealed and fixed a port-parity bug separately.

The fixed entries require whole-vector construction plus the shared inlined
metadata setter. Replacing their setters with direct fields makes VC6 batch all
24 metadata stores and drops the score sharply. The loop has the opposite
shape: native emits immediate coordinate stores, and direct metadata fields
preserve template-before-trigger ordering. Using vector constructors there
hoists four constants, saves an extra register, and adds 11 instructions.

The final candidate has the exact 108-instruction length and scores 89.81%.
The entire repeated loop body matches. The eleven residual mismatches are VC6
scheduling of independent fixed-entry vector and metadata stores, plus the
order of the loop cursor adjustment and initial trigger load. An explicit
cursor is ruled out because VC6 then proves the final count is constant and
eliminates the native count register; indexed source is the plausible shape.
