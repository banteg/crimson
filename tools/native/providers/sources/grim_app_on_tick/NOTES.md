# grim_app_on_tick

`MyApp::on_tick` is the empty callback tail-called by exact
`grim_app_pump`. The reference linker coalesced its one-byte `ret` body with
`grim_noop` at `0x10001160`; this provider-only object retains the original
member symbol while matching that selected native body exactly.
