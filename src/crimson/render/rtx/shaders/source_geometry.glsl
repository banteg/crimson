// Finite source placement shared by the lit RTX passes (ground, creatures, players, bonuses).
// Nearest point approximation to a continuous annulus, not angular integration.
vec2 nearestRingPoint(vec2 center, vec2 receiver, float radius) {
    vec2 delta = receiver - center;
    float distance = length(delta);
    return center + (distance > 1e-6 ? delta / distance : vec2(1., 0.)) * radius;
}
// Energy centroid of (.015 + f^8), f in [0,1], measured from tail to head.
// Fixed source placement avoids receiver-dependent shadow sliding. Source width
// supplies analytic softness; this is not full finite-beam integration.
vec2 illuminationSource(vec2 center, vec2 direction, float length) {
    return center + direction * length * .35242291;
}

