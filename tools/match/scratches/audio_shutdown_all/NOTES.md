# audio_shutdown_all

The top-level audio teardown releases all sound-effect and music entries before
shutting down the DirectSound backend. MSVC emits the final `dsound_shutdown`
call as a tail jump.

The recovered source is an exact 3/3-instruction match with all three native
call references aligned.
