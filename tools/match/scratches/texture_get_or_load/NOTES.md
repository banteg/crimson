# texture_get_or_load

Native target: `crimsonland.exe` at `0x0042a670` (133 bytes).

The helper first asks Grim2D for the cache handle. A miss loads `path` under
`name`, conditionally logs success when `cv_silentloads` is zero, and resolves
the new handle; failure is always logged and returns `-1`.

Binary Ninja confirms the two distinct arguments at the load call and both log
sites. Natural virtual dispatch through the recovered Grim2D interface matches
all 44 instructions, full prefix, with all eleven references aligned.
