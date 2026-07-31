# grim_app_pump

`grim_app_pump` at `0x10003090` advances the `MyApp` 30 ms accumulator and,
when a tick is due, tail-calls the singleton's empty tick callback. The native
link coalesces that callback with the selected one-byte `grim_noop` body at
`0x10001160`; the recovered platform provider carries an independently
byte-verified `MyApp::on_tick` member for structural links.

The recovered method matches all six native instructions and all three
references under MSVC 6.5 `/O2 /GB`.
