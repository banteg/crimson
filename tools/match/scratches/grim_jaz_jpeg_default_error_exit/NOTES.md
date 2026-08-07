# `error_exit`

The DLL-hosted JAZ copy retains IJG 6a's diagnostic and cleanup calls but
returns after `jpeg_destroy` instead of terminating the host process with
`exit`. Binary Ninja and Ghidra independently identify the omitted IDA
function at `0x1003ab60..0x1003ab76`.
