# Optional alignment integration validation

Validated on 2026-09-11 against source base `b2ebc01dc462612a807392f2709710deb1711806`.
This integration changes diagnostic tooling only. Both native receipts remained
current with function and game-owned closure; `match regressions` reported zero
changed functions and zero errors. Existing reference-closure debt remains.

- [live-results.json](live-results.json): five current scratches, full instruction
  coverage, all target self-controls, and both known exact controls.
- [projectile-address-chain.json](projectile-address-chain.json): automatic
  conditional trace of the first creature-search return lifetime. Four field
  accesses share coefficient 152; the target retains 152 in ESI while the
  candidate retains 19 in EBX and uses scale eight. The report also recovers the
  second call's return lifetime through the loop. Calls' argument correspondence
  and the x86 callee-saved ABI remain explicit assumptions.
- [frozen-comparison.json](frozen-comparison.json): every proposed instruction
  pair from both original spikes was reproduced on all five frozen inputs. The
  direct-COFF Levenshtein pairings equal the prior ELF-conversion pairings,
  including the two avoided 3.0/4.0 cross-branch pairs at target offsets 0x28f1
  and 0x2902. These hashes refer to the old frozen source, not the current laser
  rounding fix.
- [tools.json](tools.json): actual tested binary/script identities. asm-differ is
  pinned in the optional dependency group; objdiff 3.8.1 and GNU objdump are
  external executables.

The current projectile function has 3,021 target and 2,949 candidate instructions.
Its canonical ratio remains 60.2680067%. The tools disagree at 161 target offsets.
Objdiff proposes 491 agreeing and 12 differing reference pairs; Levenshtein
proposes 488 and 10. Unpaired or incomplete reference comparisons are reported
separately as unresolved. These counts do not determine correctness or acceptance.

Validation: 538 matching/native/CLI tests passed, including all seven actual
external-engine controls. Ruff, types, three import contracts, 137 documentation
pages, 35 ast-grep rule tests, the strict experiment ledger, native verification,
and the match regression check passed. The focused final diagnostic tests also
passed after tightening hypotheses to require a changed memory scale.

Re-run the five live cases with installed optional dependencies and explicit
binary paths; the output directory must be new:

```sh
uv run --group match-explain \
  tools/match/evidence/diagnostic-alignments-2026-09-11/verify.py \
  --objdiff /path/to/objdiff-cli --objdump /path/to/GNU/objdump \
  --out /tmp/crimson-diagnostic-validation
```

Full generated bundles remain outside the repository. The regular tests and
optional real-engine controls are in `tests/test_match_explain.py`; setup and
interpretation are documented in `docs/re/diagnostic-alignments.md`.
