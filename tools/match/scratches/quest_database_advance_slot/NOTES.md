# `quest_database_advance_slot`

Exact 30-byte, 12-instruction match with MSVC 6.5 `/O2 /GB`; it has no masked
references.

Live Binary Ninja shows 50 callsites in `quest_database_init`, one after each
metadata entry. The helper increments the zero-based quest index and wraps it
to zero while advancing the tier after every ten entries.
