# ui_element_load

Native target: `crimsonland.exe` at `0x00419d00` (207 bytes).

The loader copies the JAZ path into an unchecked 256-byte stack buffer and
terminates it at `strlen(path) - 4`, stripping `.jaz` to form the texture-cache
name. It optionally logs the load, passes the extensionless name plus the full
path to Grim2D, writes the resolved handle at offset `0xe0`, and always reports
a missing handle.

Offset `0xe0` identifies the parameter as the 0xe8-byte
`ui_menu_item_subtemplate_block_t`, not the larger `ui_element_t` whose handle
is at `0x11c`. With that type and extension policy restored, the source matches
all 67 instructions, full prefix, with all ten references aligned.
