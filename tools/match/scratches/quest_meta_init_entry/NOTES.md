# `quest_meta_init_entry`

Exact 170-byte, 51-instruction match with MSVC 6.5 `/O2 /GB`; all seven masked
references align.

Live Binary Ninja shows 50 callsites in `quest_database_init`. The helper frees
and reports an overwritten name, duplicates the new title, seeds unlock and
terrain defaults, records the one-based tier/index, and publishes the current
metadata cursor for the caller's time, weapon, and builder assignments.

Tiers 1 through 4 alternate the adjacent terrain ids according to whether the
quest index is in the first or second half. Tier 5 maps the index modulo four,
forces companion terrains 1 and 3, and temporarily writes builder value 5.
Every observed caller immediately overwrites that field with the real builder,
so the odd pointer-shaped sentinel is preserved as a native source quirk, not
invented into a meaningful function pointer.

The function is `void`: callers ignore EAX, and the apparent returned tier is
only the register value left by the final comparison.
