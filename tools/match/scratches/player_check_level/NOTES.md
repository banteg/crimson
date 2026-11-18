# Freeware level check

Each level milestone has its own inlined creature initializer. The code
checks the current player's level again after each spawn and writes contact
damage at different points for the different bosses. The 1.0.2 executable
uses the current player throughout. The two later builds select player zero
and restore the old index on the normal return path.

The level-up resets the perk hover and clears the choice flags before drawing
five distinct perk IDs. The following byte clear is the only direct reference
to its address in each executable. Its name records that write. The 1.0.2
and 1.3.0 flag arrays span 32 bytes, and the 1.4.0 array spans 48.

The 1.0.2 boss at level 13 awards 500,000 XP. The later releases reduce it
to 4,000 and add a fifth boss at level 17. The portable client oracle covers
all boss records in 1.4.0 and checks the level thresholds and RNG in both
earlier releases.
