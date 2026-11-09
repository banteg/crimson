The original screen draws the rank, name and display value of 100 entries.
1.0.2 uses a fixed 480-pixel viewport and the plain 36-byte score records.
1.3.0 adds scrolling and tints high Career scores saved by 1.22 and 1.24.
1.4.0 switches to highlighting the last submitted score, handles two-player
titles and skips rows outside the viewport.

Counting the headings and score rows together recovers VC6's induction
variable, including the final off-screen dismissal check. The 1.3.0 and
1.4.0 routines match their encoded bodies.

In 1.0.2 the remaining code generation difference is at 0x0040ff43.
The executable loads the mode into EAX before the next line's x87 coordinate
calculation, then compares EAX with 2. The candidate compares the same 32-bit
global directly with 2. Its body is one byte shorter, shifting subsequent
branch destinations. Local copies of the mode, inline heading helpers, and
compiling the immediately preceding loading-progress function in the same
translation unit retain this difference. A switch instead subtracts 2 and
reverses the conditional branch.
