The original screen draws the rank, name and display value of 100 entries.
1.0.2 uses a fixed 480-pixel viewport and the plain 36-byte score records.
1.3.0 adds scrolling and tints high Career scores saved by 1.22 and 1.24.
1.4.0 switches to highlighting the last submitted score, handles two-player
titles and skips rows outside the viewport.

Counting the headings and score rows together recovers VC6's induction
variable, including the final off-screen dismissal check. For the two early
builds the heading helper takes the mode by value and advances the line
counter by reference. In 1.0.2 VC6 loads the mode into EAX before calculating
the heading's y coordinate, then compares EAX with 2 at 0x0040ff52.
All three versions match their encoded bodies and references.
