# reg_write_dword

This wrapper writes one `REG_DWORD`, returning `S_OK` for any successful Win32
write and collapsing every failure code to `E_FAIL`.

The recovered source is an exact 14/14-instruction match with its Win32 import
reference aligned.
