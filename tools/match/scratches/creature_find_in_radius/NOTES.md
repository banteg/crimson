# creature_find_in_radius WIP

Current best local score:

```txt
match=70.83% prefix=4/47 target_insns=47 candidate_insns=49 refs=3/0/2
```

The source recovers the bounded scan from `start_index`, active and lifecycle
filters, radius-plus-size test, and first-hit or `-1` result. Splitting the
squared distance into an x product followed by a y accumulation reproduces the
native x87 arithmetic and cleanup sequence.

VC6 still biases the candidate loop register at `pos_y`; native retains the
record's active-byte base. That rebasing adds a load/test pair and changes the
end comparison. The candidate also lays the hit epilogue before the miss
fallthrough. Keep these as honest WIP residuals rather than encoding structure
offsets or branch-layout tricks in the recovered source.
