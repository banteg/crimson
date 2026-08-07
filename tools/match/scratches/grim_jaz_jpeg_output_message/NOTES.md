# `output_message`

The JAZ copy replaces IJG 6a's stderr diagnostic with a modal Win32 message
box titled `JPEG Error`. The callback otherwise retains the stock 200-byte
message buffer and `format_message` dispatch.
