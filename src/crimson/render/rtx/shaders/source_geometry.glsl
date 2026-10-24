// Finite source placement shared by the lit RTX passes (ground, creatures, players, bonuses, smoke).
// Nearest point approximation to a continuous annulus, not angular integration.
vec2 nearestRingPoint(vec2 center, vec2 receiver, float radius) {
    vec2 delta = receiver - center;
    float distance = length(delta);
    return center + (distance > 1e-6 ? delta / distance : vec2(1., 0.)) * radius;
}
// A segment source's radiance along its axis, from its tail (f = 0) to its head
// (f = 1): a linear ramp from `tail` to 1, as a beam's streak stamps fade in from
// its tail. Every receiver weights a segment by this one profile; `tail` is the
// light's (MaterialLight.reflection_tail), 1 for a uniform segment.
float segmentRadiance(float f, float tail) {
    return mix(tail, 1., clamp(f, 0., 1.));
}
// The point standing in for a segment's light: its energy centroid under that
// ramp, (1 - tail) / (6 (1 + tail)) lengths ahead of its center. Fixed placement
// avoids receiver-dependent shadow sliding. Source width supplies analytic
// softness; this is not full finite-beam integration.
vec2 illuminationSource(vec2 center, vec2 direction, float length, float tail) {
    return center + direction * length * (1. - tail) / (6. * (1. + tail));
}

