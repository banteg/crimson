# Fire Cough vector-angle alias-config control

This is a separate copied-config ABI control, **not canonical-epoch experiment
ledger evidence**. Neither the source variants nor the additional reference alias
were retained. `control.conf` deliberately is not named `scratch.conf`, so the
evidence directory cannot be discovered as another canonical scratch.

The baseline source is recoverable from commit
`5d47470f01c7e4a58336b23a1526905da3564426` at
`tools/match/scratches/player_update/scratch.cpp`, SHA-256
`1a7e3490cde7dfc566818418d2dfd7a242fbb6eb0dab810aa4eab854aa94c7fe`.
`metadata.json` binds that source and the exact config/spec/results hashes. The
full source variants and compiler binaries are intentionally not duplicated.

An independent bounded VC6 ABI control found that both an explicit output-pointer
method and an ordinary vector subtraction operator returning by value can emit
the same 26 native bytes at `0x00417640`. The authenticated 2003 MOD SDK also
provides an inline `VEC2_Angle(const vec2_t&)` wrapper. Native Fire Cough consumes
the helper return through EAX at `0x00413b7f`. These observations motivated
testing subtraction-expression temporaries consumed by the inline angle helper;
they do not uniquely establish the original subtraction signature.

The copied config adds `??Gvec2_t@@QBE?AU0@ABU0@@Z:vec2_sub` beside the
existing `?vec2_sub@vec2_t@@QAEPAMPAM0@Z:vec2_sub` alias. The unchanged
copied-config baseline reproduces the canonical baseline exactly: 4,066/4,206
instructions, 64.02321083172147%, 10,408.25338491296 weighted bytes, prefix 7,
and references 805/0/2 (ok/unresolved/mismatch).

All 3/3 constrained variants were evaluated with no compiler errors:

| Variant | Weighted-byte delta | Instructions | Prefix | References |
| --- | ---: | ---: | ---: | --- |
| Unused operator/angle declarations | 0 | 4,066 | 7 | 805/0/2 |
| Expression temporary passed to angle helper | -1,060.1344150181467 | 4,065 | 1 | 743/0/16 |
| Named return-value control | -1,320.6847195357823 | 4,066 | 1 | 706/0/21 |

Both used forms regress the whole-function instruction/reference evidence and
were rejected. The neutral unused declarations establish that the extra alias
and scaffold alone do not account for those regressions. This only bounds the
tested call-consumer forms; it is not an ABI impossibility claim.

To reproduce from the repository root, reconstruct the baseline in a temporary
directory and use the copied config there:

```sh
vector_control_dir=$(mktemp -d /private/tmp/player-update-vector-control.XXXXXX)
git show 5d47470f01c7e4a58336b23a1526905da3564426:tools/match/scratches/player_update/scratch.cpp > "$vector_control_dir/scratch.cpp"
cp tools/match/scratches/player_update/evidence/vector-angle-control-2026-09-08/control.conf "$vector_control_dir/scratch.conf"
.venv/bin/crimson match mutate "$vector_control_dir" \
  --spec tools/match/scratches/player_update/evidence/vector-angle-control-2026-09-08/mutations.json \
  --max-changes 2 --max-variants 3 --jobs 3 --json \
  > "$vector_control_dir/results.json"
```

The mutation command exits nonzero when no improving variant exists; inspect its
JSON results for completion and compiler errors. Current shared headers and
tooling are used by that command, so a later rerun can differ from the saved
historical result even though the source/config remain fixed. To reproduce the
complete original environment, run it in an isolated checkout of the recorded
baseline commit with the same installed VC6.5 compiler bundle and native PE.
