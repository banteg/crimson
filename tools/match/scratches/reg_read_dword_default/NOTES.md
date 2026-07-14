# reg_read_dword_default

This registry helper always returns zero. A failed `RegQueryValueExA` is
represented only by writing the caller-provided fallback into `out`; the value
type returned by Win32 is otherwise ignored.

MSVC reuses the now-dead stack slot holding the `out` argument for the local
registry type, leaving only the four-byte data-size local in the frame.

The recovered source is an exact 23/23-instruction match with its Win32 import
reference aligned.
