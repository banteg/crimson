# grim_draw_circle_outline

Emits paired inner/outer vertices into the dynamic vertex buffer and draws the
ring as a triangle strip. The native outer radius is `radius + 2.0f` and the
inclusive loop uses `int(radius * 0.2f + 14.0f)` segments.
