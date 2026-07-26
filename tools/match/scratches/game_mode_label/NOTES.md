# game_mode_label

Native target: `crimsonland.exe` at `0x00412960` (176 bytes).

The helper selects the user-facing Survival, Rush, Quests, or Typ'o'Shooter
label for the current mode, falls back to Unknown, copies it into the shared
scratch buffer, and returns that buffer.

Independent early returns preserve the native private inline copies for
Survival and Typ'o'Shooter while keeping the three other mode arms in their
observed order. Unlike the mixed shared-tail spelling, each arm also returns
the known destination buffer rather than the result register from `strcpy`.
VC6.5 `/O2 /GB` then emits the exact native 69 instructions with all 12 masked
references resolved:

```txt
match=100.00% prefix=69/69 target_insns=69 candidate_insns=69 refs=12/0/0
```

This source shape follows the live Binary Ninja control flow: every mode arm
copies its selected literal into the shared buffer and returns that buffer.
