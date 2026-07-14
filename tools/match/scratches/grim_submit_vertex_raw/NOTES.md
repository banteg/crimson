# grim_submit_vertex_raw

Copies one complete 28-byte transformed/lit vertex into the active dynamic
vertex-buffer lock. The method lazily begins a batch, advances the write cursor
and low-word vertex count, and flushes at capacity.
