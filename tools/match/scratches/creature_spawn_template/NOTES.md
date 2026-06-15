# creature_spawn_template WIP

Initial scope:

- shared root creature initialization
- random heading sentinel handling
- formation ids `0x11..0x19`
- unhandled-template fallback for `0x11` and `0x13`
- shared post-dispatch tail modifiers

Known missing work:

- the large dispatch ladder for all remaining spawn ids
- spawn-slot controller setup cases
- random/simple creature templates

Keep tracking prefix, not just total match percent. This scratch is expected to
be low percentage until more template families are added.

Current local score:

```txt
match=20.05% prefix=20/3159 target_insns=3159 candidate_insns=930
first_target=lea edx, dword [ebp+ebp*8]
first_candidate=mov edi, dword [esp+0x60]
```

Frame/prefix notes:

- The source now reproduces the native `0x48`-byte stack frame.
- Moving the saved position pointer below the random-heading sentinel improved
  the prefix from `1/3159` to `20/3159`.
- The first blocker is now root-slot address arithmetic versus reloading `pos`
  from the stack.
