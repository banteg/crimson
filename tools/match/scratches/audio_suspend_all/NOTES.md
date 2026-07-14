# audio_suspend_all

Stops eligible music channels, optionally logs under `cv_verbose`, and sets the
global suspension latch.

The native `mov al, 1; mov [flag], al` proves the helper returns the assignment
value. Correcting the return type yields an exact 14/14-instruction match with
all seven native references aligned.
