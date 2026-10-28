// Premultiplied color of particles.jaz effect 13 (its coverage is a disc).
// Fitted in stamp-radius units against the original 62x62 inset cell.
const vec3 WARM_BETA = vec3(99.454177, 29.698389, 5.147299);
const mat3 WARM_COLOR = mat3(vec3(.145013, .319797, .258152),
                            vec3(.458470, .290554, .094918),
                            vec3(.469725, .334796, .170283));
const vec2 WARM_OFFSET = vec2(.027944, .036952);

vec3 warmProfile(vec2 p) {
    float r = length(p);
    if (r >= 1.) return vec3(0.);
    return WARM_COLOR * exp(-WARM_BETA * dot(p, p)) * (1. - smoothstep(.94, 1., r));
}

// particles.jaz effect 16, retuned for linear light: concentrate the core and
// lower the broad skirt so removing the cutoff does not leave a luminous disc.
float auraProfile(vec2 p) {
    p -= vec2(.027797, .037006);
    return dot(vec3(.34, .38, .24),
               exp(-vec3(107.953114, 32.756217, 7.2) * dot(p, p)))
        * (1. - smoothstep(.94, 1., length(p)));
}

// RTX pressure front: a narrow crest with a soft inward wake, leaving the interior
// clear. The old artwork's broad white fill becomes a milky disc in linear light.
// Filter the crest in screen space, conserving its energy when it is sub-pixel.
float ringProfile(vec2 p) {
    float r = length(p);
    // Small, broad variations break the perfect hoop without adding noisy detail
    // or changing its silhouette enough to compete with the expanding motion.
    vec2 n = p / max(r, .001);
    float ripple = n.x * n.y * (n.x * n.x - n.y * n.y);
    float d = r - (.90 + .012 * ripple);
    float aa = .5 * fwidth(r);
    float band = mix(.065, .024, smoothstep(-.02, .02, d));
    float width = sqrt(band * band + aa * aa);
    float crest = .30 * (band / width) * exp(-d * d / (width * width));
    float variation = .82 + .18 * n.x + .12 * ripple;
    return crest * variation * (1. - smoothstep(.94, .99, r));
}

// Chain arcs retain the ion streak's widths, with more energy in the core and
// less in the halo: overlapping arcs stay legible instead of filling a blue slab.
float ionProfile(vec2 p) {
    float r2 = dot(p, p);
    return dot(vec2(.60, .26), exp(-vec2(49.18833, 5.9273) * r2))
        * (1. - smoothstep(.75, 1., sqrt(r2)));
}

// Abramowitz-Stegun 7.1.26, max absolute error 1.5e-7; no tanh overflow on GPUs.
vec3 effectErf(vec3 x) {
    vec3 t = 1. / (1. + .3275911 * abs(x));
    vec3 p = (((((1.061405429*t - 1.453152027)*t) + 1.421413741)*t - .284496736)*t + .254829592)*t;
    return sign(x) * (1. - p * exp(-x*x));
}
