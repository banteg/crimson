# `player_heading_approach_target`

## Complete 1.9.8 recovery (2026-10-13)

The shared translation unit now normalizes the selected player heading directly
in the field loops. Processor Pack C2 keeps the working value on the x87 stack
until each normalization loop exits, matching the older executable. The former
named float working copy introduced an extra store/reload in each loop.

Independent Binary Ninja control flow pins the complete body at
`0x00413aa0..0x00413c0d`: 365 encoded bytes, 96 instructions and 22 blocks.
The return at `0x00413c0c` is followed by three alignment NOPs. Native stores
`player_heading_turn_delta` at `0x00413bef`, then reloads it and adds it to the
selected player's heading. The reviewed global pin resolves the final operand.

Both normalized instructions and relocation-aware encoded bytes match, with
24/0/0 references. Canonical retains its complete 95-instruction match and
27/0/0 references. Canonical `player_update` remains instruction and byte exact.
This helper recovery does not award a match to either 1.9.8 updater.

## Early freeware

The 1.0.2 and 1.3.0 functions normalize the current heading, then call
standalone min/max helpers to compare the direct turn with the turn across the
zero-angle boundary. Both helpers reproduce their nine-instruction bodies in
each release. The 1.3.0 heading update at `0x40e2c0` reproduces all 97
instructions, encoded bytes and 32 references. In 1.0.2 at `0x407ec0`,
MSVC schedules an index addition before the independent stack store at
`0x407f49`. All 32 references resolve and the remaining instructions agree.
The 1.4.0 implementation selects min and max inline and remains byte-exact.
