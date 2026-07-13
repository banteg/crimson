# creature_spawn_tinted

Exact match:

```txt
match=100.00% prefix=92/92 target_insns=92 candidate_insns=92 refs=34/0/0
```

The recovered source reconstructs the dedicated Typ-o creature initializer:
fixed health and reward, the chase-player AI mode, random heading and size, the
caller-provided RGBA tint, and the spider-specific speed, size, and flag
adjustments.

The source keeps the random size in a local because native retains that value
on x87 after storing the base size, then reuses it for the spider scale. The
spider path similarly computes a scaled-speed local before updating the flags
and storing both adjusted values. These are ordinary source temporaries that
account for the native instruction schedule without volatile accesses or
representation tricks.

This function also independently confirms that creature tint is runtime state,
not merely spawn-planning metadata: native copies all four caller-provided
components into the creature record before returning.
