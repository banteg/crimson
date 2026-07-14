# grim_app_pump

`grim_app_pump` at `0x10003090` advances the `MyApp` 30 ms accumulator and,
when a tick is due, tail-calls the singleton's empty tick callback.

The recovered method matches all six native instructions and all three
references under MSVC 6.5 `/O2 /GB`.
