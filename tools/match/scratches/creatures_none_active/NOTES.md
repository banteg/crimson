# `creatures_none_active`

The bounded pre-tested loop is exact with both the default `msvc6.5` profile and
VC6 SP6: 40/40 bytes, 12/12 instructions, and all four references align.

The earlier tail-tested spelling was exact only with the Processor Pack. Stock
VC6 peeled its first iteration, producing 15 instructions and a 44.44% match.
Making the already-required pool bound the loop condition recovers the native
CFG without changing behavior and removes the unsupported compiler override.
