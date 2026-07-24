# highscore_rank_index

Binary Ninja shows three straight insertion scans over the 0x48-byte high-score
records:

- Rush returns the first row whose elapsed value is below the active value.
- Quest returns the first row whose elapsed value is above the active value.
- Other modes return the first row whose score is below the active score.

The recovered source has the native 51-instruction control-flow shape and all
four references resolve. MSVC assigns the loop bound to EDX and the record
cursor to ECX, while the native body makes the opposite allocation in all three
loops. The source intentionally remains a WIP instead of forcing registers with
artificial aliases or byte-shaped control flow.

An explicit record cursor compiles identically. Per-arm count snapshots instead
coalesce the later loads and regress to 50 instructions. The VC6.0 and VC6.6
backends retain the same register swap; VC6.5pp and VC7.0 hoist the count and
diverge further. There is no remaining natural source or compiler-profile lead.
