# `ui_text_input_update`

Native target: `crimsonland.exe` at `0x0043ecf0` (720 bytes).

Recovered as an exact 203/203-instruction match with all 36 native references
audited.

Live Binary Ninja evidence establishes a 16-byte input state containing the
text buffer, cursor, capacity, and pixel width. The widget:

- participates in the shared keyboard-focus system and claims focus on hover;
- null-terminates one byte beyond the cursor before polling console input;
- submits on Enter, consumes both Enter scancodes, and plays the submit sound;
- otherwise delegates editing to Grim's key-character buffer and alternates
  the two typing sounds through `rand() % 2`;
- draws the framed field, advances the visible-text start until it fits, and
  renders a sine-blinking one-pixel caret after the measured visible suffix.

The return value is the one-byte submission flag carried in `al`, so the
native signature is `bool`, not the former decompiler-inferred `int`.
