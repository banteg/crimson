# demo_trial_overlay_render

High-value recovery for the 2,413-byte demo-expiry overlay at `0x004047c0`.
Live Binary Ninja control-flow, stack-slot, string, and callsite evidence
recovers the complete panel, time formatter, message policy, local-static
buttons, purchase action, and return-to-menu action.

## Recovered source shape

- renders the 512x256 warning panel, logo, header, and three native message
  layouts for the Quest tier limit, exhausted trial, and Quest-only grace time;
- preserves the native integer time decomposition, including the manual
  minute remainder that produces VC6's three multiply-high divisions;
- formats single-digit seconds with the evidenced `"0%d"` literal and
  centiseconds with the native one-digit zero prefix;
- retains the empty formatted line and the extra unused time argument passed
  to the grace-period lead sentence;
- reconstructs the shared three-bit local-static guard in Maybe later,
  Purchase, and unused Already paid order;
- opens `http://buy.crimsonland.com` and latches quit after Purchase; and
- returns to the main menu, resets the render transition, and switches music
  after Maybe later.

## Static-object evidence

The VC6 object relocation table maps `$E2` to the Maybe later destructor at
`0x00405150`, `$E3` to Purchase at `0x00405140`, and `$E4` to Already paid at
`0x00405130`. Live Binary Ninja disassembly proves all three callbacks are a
single `ret`. The decorated guard/object aliases and pooled empty literal now
pass the strict reference audit at `171/0/0`.

## Remaining mismatch

The natural source is an honest 94.25% WIP: 616 candidate instructions against
636 native instructions, with the first 205 instructions exact and the native
`0x124` stack frame reproduced. VC6 still tail-merges a repeated two-line text
suffix that the native keeps distinct. In the button tail it assigns the
long-lived row origin to the body vector's dead `+0x10` slot and the short
Purchase coordinate to `+0x1c`; native uses those two slots in the opposite
roles and retains the shared y coordinate between them. Scoped vectors,
constructor and assignment forms, `set`, `operator+`, `operator+=`, and
separate scalar anchors either preserved those artifacts or materially
worsened the long text-body register allocation. No union, volatile state,
dead expression, fake reference, or artificial register constraint is used.
