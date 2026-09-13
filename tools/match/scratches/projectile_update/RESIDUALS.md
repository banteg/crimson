# Residual work ledger

Work from the pinned `d3505333` source and identify a native instruction/data-flow
boundary before trying a spelling. Compile one change, check its own window,
record effects elsewhere, and execute relevant native witnesses. Function score
is a regression signal, not the unit of progress. A heuristic span is not a
distinct bug; branch displacements and stack homes can reflect another region.

The reproducible ledger, source steps, native receipts, and instruction-window
audit are in
[`projectile-residual-decomposition-2026-09-13`](../../evidence/projectile-residual-decomposition-2026-09-13/README.md).
The canonical scratch is unchanged by that package.

| Region | Concrete residual | Current evidence / next check |
| --- | --- | --- |
| Primary movement `420de3..420e1f` | Accumulation rounding boundary | Already recovered in the pushed baseline; preserve its native witnesses. |
| Ion-chain address `4212d5` | Candidate computes the pool base where native computes the position address | Positional-reference mismatch remains. Inspect the actual owner/address use, not an alias override. |
| Primary decals `421686..421744` | Missing product materialization at `2.0` and `2.5` scales | The `2.5` boundary explains the retained 70/1,000 PC64 call differences. Compare the product store/reload before addition. |
| Primary sound `42190f` | Type is read after effects in native, retained from before effects in the source | Track the cached type's live range separately from sound argument semantics. |
| Secondary targeting `421ab1`, `421b9d` | Native induction points at creature Y; candidate at X | Two positional-reference mismatches; analyze induction and lifetime together. |
| Secondary effects `4221ba`, `4222a3`, `42238e` | Component order / vector result boundary | Three X/Y positional-reference mismatches. Native uses the product result before position addition. |
| Particle movement `4224e8..4226af` | Call-path block order; retained intensity; early flag load; long position-reference lifetime | Arithmetic regression suite passes. These remain distinct static issues. Reversing the source threshold guard alone changes layout but does not close them. |
| Particle expiry `4226af..422767` | Two expiry paths, post-movement style reload, call argument lifetime | Three-step candidate removes both threshold reference mismatches; 4,817 trajectory and 224 bubble controls preserve native observations. Store/load scheduling still differs. |
| Particle age `42283f..42285d` | Integer field copy instead of a float-valued conditional | Nine instructions / 30 bytes verified, with only two proven constant-address fields masked. This local result awards no function credit. |
| Particle collision and geometry `42287d..4229e1` | Attachment publication, component rounding, angle branch orientation, position owner | Recovered candidate eliminates the 25 state failures. Registers and stack homes are still non-native. |
| Particle tint `422ab1..422b93` | Returning a clamped value writes unchanged components; direct field conditions cache products | In-place pointer helper preserves field reloads and conditional stores. First-component constant initialization still differs. |
| Particle effects `422b93..422c46` | First RNG integer lifetime; reflected-velocity/time copies | Recovered independently; integrated candidate has zero observed residuals in 1,230 impact and 663 real-helper cases. Stack and register placement remain open. |
| Loop/frame `422c46..422c69` and prologue | Induction endpoint and shared local homes | Candidate frame is still `0xcc`, native `0xf4`. Do not add unused owners or padding to force the size. |

Removing the cached particle style frees a register and initially moves the
particle index out of its native stack role. Retaining the later hit-position
owner puts the index back on the stack, but does not recover its exact home.
That is a dependency between regions, not evidence that an otherwise correct
expiry branch should be discarded for a lower score.

The accumulated diagnostic candidate passes 8,934 native/control cases within
their documented scopes, but remains non-exact. Keep its recovered boundaries
available while resolving the remaining static owners; do not replace the
canonical source or refresh matching credit from the replay result alone.
