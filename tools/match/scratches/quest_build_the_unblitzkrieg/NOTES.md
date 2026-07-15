# `quest_build_the_unblitzkrieg`

Native target: `crimsonland.exe` at `0x00438a40` (975 bytes).

Live Binary Ninja disassembly recovers 81 entries: eight ten-entry perimeter
sweeps with one center entry between the second and third sweeps. Heading is
left untouched and every entry has count one. Each sweep advances an integer
offset from 0 by `0x270` while it is below `0x1860`; dividing that offset by
ten produces the axis coordinate. Templates alternate `0x07`, `0x0d`, starting
with `0x07` in every sweep.

- x=824, y=`200 + offset/10`, triggers 500 through 16700 by 1800;
- y=824, x=`824 - offset/10`, triggers 18500 through 32000 by 1500;
- center (512,512), template `0x07`, trigger 33500;
- x=200, y=`824 - offset/10`, triggers 33500 through 44300 by 1200;
- y=200, x=`200 + offset/10`, triggers 45500 through 52700 by 800;
- x=824, y=`200 + offset/10`, triggers 53500 through 60700 by 800;
- y=824, x=`824 - offset/10`, triggers 61500 through 67800 by 700;
- x=200, y=`824 - offset/10`, triggers 68500 through 74800 by 700;
- y=200, x=`200 + offset/10`, triggers 75500 through 82700 by 800.

The candidate scores 70.10% with a twelve-instruction exact prefix, exactly
291 candidate and native instructions, and no static-reference debt. It
reproduces the signed division-by-ten lowering, parity-to-template arithmetic,
24-byte stride, loop limits, count reservation, trigger increments, register
frame, and final count. In particular, the first sweep advances the live count
per entry while each later sweep reserves ten entries before looping, matching
the native `add edi, 0xa` boundaries.

The repeated residual is legal independent-store scheduling. Native VC6 uses
the `template_id` field as its cursor base, advances that cursor before storing
template/time/count through negative offsets, and leaves those metadata stores
until after the x87 coordinate conversion. The candidate uses the record base
and hoists constant count and trigger stores around the same conversion. A
metadata-only setter and direct field stores compile identically; encoding a
negative-field cursor would describe the optimizer rather than plausible game
source. No volatile state, dummy dependencies, or register-forcing constructs
are used.
