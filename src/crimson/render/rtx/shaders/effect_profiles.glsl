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

// particles.jaz effect 16: white color, radial alpha.
float auraProfile(vec2 p) {
    p -= vec2(.027797, .037006);
    return dot(vec3(.262220, .322753, .372035),
               exp(-vec3(107.953114, 32.756217, 5.411207) * dot(p, p)))
        * (1. - smoothstep(.94, 1., length(p)));
}

// particles.jaz effect 1 is a thick shell: a broad inward gradient and a compact rim.
float ringProfile(vec2 p) {
    float r = length(p - vec2(.020362, .011385));
    float r2 = r * r;
    float inner = clamp((r - .15) / .09, 0., 1.);
    float edge = 1. - smoothstep(.902, .933, r);
    return (.485166 * r2 + 1.415130 * r2*r2*r2*r2) * inner * edge;
}

// projs.jaz effect 2, shared with the ion streak's fitted core/halo.
float ionProfile(vec2 p) {
    float r2 = dot(p, p);
    return dot(vec2(.47467, .3886), exp(-vec2(49.18833, 5.9273) * r2))
        * (1. - smoothstep(.75, 1., sqrt(r2)));
}

// Abramowitz-Stegun 7.1.26, max absolute error 1.5e-7; no tanh overflow on GPUs.
vec3 effectErf(vec3 x) {
    vec3 t = 1. / (1. + .3275911 * abs(x));
    vec3 p = (((((1.061405429*t - 1.453152027)*t) + 1.421413741)*t - .284496736)*t + .254829592)*t;
    return sign(x) * (1. - p * exp(-x*x));
}
