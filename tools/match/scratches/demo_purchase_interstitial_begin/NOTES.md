# demo_purchase_interstitial_begin

Native target: `crimsonland.exe` at `0x00403370` (18 bytes).

The callback starts the demo upsell interval by setting the countdown to
10,000 ms and raising the purchase-screen latch. Natural C++ matches all 3
instructions and references `2/0/0` under MSVC 6.5 `/O2 /GB`.
