# grim_submit_quad_raw

Copies four complete transformed/lit vertices (112 bytes) into an already
active batch, advances the write cursor and low-word count, and flushes at
capacity. Unlike the single-vertex entry point, this path only checks the
render-disable byte and assumes its caller has begun the batch.
