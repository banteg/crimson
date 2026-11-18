# texture_get_or_load

Native target: `crimsonland.exe` at `0x0042a670` (133 bytes).

The helper first asks Grim2D for the cache handle. A miss loads `path` under
`name`, conditionally logs success when `cv_silentloads` is zero, and resolves
the new handle; failure is always logged and returns `-1`.

Binary Ninja confirms the two distinct arguments at the load call and both log
sites. Natural virtual dispatch through the recovered Grim2D interface matches
all 44 instructions, full prefix, with all eleven references aligned.

In 1.4.0 the helper uses the console's Grim interface, logs every load attempt,
and returns false even after a successful load. All 97 bytes at 0x0041fc80
and all eight references match.
