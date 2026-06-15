# bonus_apply WIP

Current best local score:

```txt
match=64.41% prefix=6/668
```

Useful shape learned:

- VC6 uses a 16-byte stack frame here. The scratch models those native scratch
  slots with `bonus_apply_locals_t`.
- The bonus dispatch is not a jump table under the matching settings; writing it
  as the observed compare chain is materially better than a C++ `switch`.
- Both Freeze and Nuke scan 384 creature records (`0x180` stride-0x98 entries),
  not 128.

First remaining prefix split:

```txt
target:    mov dword [esp+0x8], 0x3f800000
candidate: push ecx
```

That is the Bonus Economist multiplier store being scheduled after the perk id
push in the candidate. A simple explicit local for `perk_id_bonus_economist`
made register choice worse (`prefix=5`), so leave it out for now.
