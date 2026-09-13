# Residual work ledger

Work from the pinned `d3505333` source and identify a native instruction/data-flow
boundary before trying a spelling. Compile one change, check its own window,
record effects elsewhere, and execute relevant native witnesses. Function score
is a regression signal, not the unit of progress. A heuristic span is not a
distinct bug; branch displacements and stack homes can reflect another region.

The reproducible ledger, source steps, native receipts, and instruction-window
audit are in
[`projectile-residual-decomposition-2026-09-13`](../../evidence/projectile-residual-decomposition-2026-09-13/README.md).
The [primary/secondary continuation](../../evidence/projectile-primary-secondary-residuals-2026-09-13/README.md)
adds 22 independently motivated steps and retains 46 experiments, including
negative controls. The [ownership continuation](../../evidence/projectile-ownership-and-stack-2026-09-13/README.md)
adds 20 further steps and 73 compiling controls. Its [compiler stack observation](../../evidence/projectile-stack-groups-2026-09-13/README.md)
checks group membership and maps the 964-instruction primary prefix's native
stack accesses. These packages leave the canonical scratch unchanged.

| Region | Concrete residual | Current evidence / next check |
| --- | --- | --- |
| Primary movement `420de3..420e1f` | Accumulation rounding boundary | Already recovered in the pushed baseline; preserve its native witnesses. |
| Ion-chain address `4212d5` | Candidate computes the pool base where native computes the position address | Recovered using position owners; the positional-reference mismatch is removed without an alias override. |
| Primary decals `421686..421744` | Missing product materialization at `2.0` and `2.5` scales | Recovered complete offsets; the retained 70/1,000 call differences are now zero. |
| Primary sound `42190f` | Type is read after effects in native, retained from before effects in the source | Reload and separate call branches recover the local instruction sequence and RNG argument lifetime. |
| Primary impact `4210b7..4218cf` | Jitter conversion, plasma/pulse offsets, Gauss heading reload and Bloody Mess range lifetime | Recovered independently. Expanded 576-case weapon matrix now has no observed differences. |
| Primary impulse `42150f..4215a7` | Native retains cosine across the branch and multiplies twice; candidate merges products | Recovered through branch-local construction and a reference to the actual speed field. The 43-instruction window has matching register/branch/reference structure with mapped stack homes; no mixed-precision cast is needed. |
| Secondary targeting `421ab1`, `421b9d` | Native induction points at creature Y; candidate at X | Two positional-reference mismatches; analyze induction and lifetime together. |
| Secondary effects `4221ba`, `4222a3`, `42238e` | Component order / vector result boundary | Complete polar offsets recover the result boundary; the remaining minigun position owner is separate. Rocket/minigun 300-case matrix now has zero state/call/write differences. |
| Secondary speed/steering `421be1..421d3b` | Squared component lifetimes, seeker position/velocity reloads | Staged squares recover all three speed sequences; a rollback X reference restores the native field reload. All 1,200 steering witnesses pass. The seeker angle/address instruction order remains open. |
| Secondary trail/burst `421dc0..422447` | Cosine result materialization and vector multiplication scheduling | Separate trail constructor arguments remove 313 state/call/write failures in 1,200 cases. The burst still has an extra exchange. |
| Particle movement `4224e8..4226af` | Call-path block order; retained intensity; early flag load; long position-reference lifetime | High-first paths, field references and collision-local position ownership recover the reloads and arithmetic order. Call argument registers remain different in the accumulated candidate. All 4,817 trajectories pass. |
| Particle expiry `4226af..422767` | Two expiry paths, post-movement style reload, call argument lifetime | The indexed particle loop recovers the endpoint but needs a style reference bound after expiry to preserve the late read. Trajectory and bubble witnesses pass; some call registers remain different. |
| Particle age `42283f..42285d` | Integer field copy instead of a float-valued conditional | Nine instructions / 30 bytes verified, with only two proven constant-address fields masked. This local result awards no function credit. |
| Particle collision and geometry `42287d..4229e1` | Attachment publication, component rounding, angle branch orientation, position owner | The record owner for previous-position Y and zeroing through the velocity reference recover the native geometry sequence and velocity-Y cursor. Stack homes remain non-native. |
| Particle tint `422ab1..422b93` | Returning a clamped value writes unchanged components; direct field conditions cache products | In-place pointer helper preserves field reloads and conditional stores. First-component constant initialization still differs. |
| Particle effects `422b93..422c46` | First RNG integer lifetime; reflected-velocity/time copies | Recovered independently; integrated candidate has zero observed residuals in 1,230 impact and 663 real-helper cases. Stack and register placement remain open. |
| Loop/frame `422c46..422c69` and prologue | Induction endpoint and shared local homes | Indexed sprite/particle loops and the primary microstep `for` recover their endpoints. Accumulated frame is `0xe8`, native `0xf4`; canonical remains `0xcc`. C2 group memberships are verified, but the native lifetimes remain open. An outer color owner yields `0xf8`, not a match. |

Removing the cached particle style frees a register and initially moves the
particle index out of its native stack role. Retaining the later hit-position
owner puts the index back on the stack, but does not recover its exact home.
That is a dependency between regions, not evidence that an otherwise correct
expiry branch should be discarded for a lower score.

The accumulated diagnostic candidate passes 12,402 native/control cases within
their documented scopes, but remains non-exact. Expanded explosion fixtures model
the external D3DX normalization boundary rather than executing its DLL. The native
stack map also exposed reversed delta-zero stores hidden by displacement-insensitive
comparison; chained zero assignment recovers their Y-before-X order. Keep the
recovered boundaries available while resolving remaining owners and allocation;
no replay or compiler observation alone changes canonical matching credit.
