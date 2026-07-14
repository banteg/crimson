# ui_menu_main_click_buy_full_version

Native target: `crimsonland.exe` at `0x0044fc70` (39 bytes).

The shareware callback latches both quit and offer-seen flags, then opens
`http://buy.crimsonland.com` with the Windows shell's normal-window mode.
Natural VC6 code matches all 11 instructions and references `5/0/0`.
