# DX8 → OpenGL (raylib/pyray) Porting Gotchas Cheat Sheet

## 1) The big mental-model mismatch: DX8 fixed-function vs OpenGL 3.3 shader pipeline

### DX8 (D3D8)

* Lots of behavior is “free” in the fixed function pipeline:

  * **Alpha test** (discard) exists as a render state.
  * **Texture stages** (COLOROP/ALPHAOP + args) do complex combining automatically.
  * Built-in lighting/fog/vertex processing is standard.

### raylib (OpenGL 3.3 core)

* You are always “really using shaders”, even if you don’t write them.
* Many DX8 fixed-function features **do not exist** as API states anymore (alpha test, stage combiners, fog).
* If your decompiles set a state, and you don’t reproduce the effect in shader/state, visuals drift.

**Porting rule:** Treat the decompile as “the truth”, and build a mapping layer that reproduces *effects*, not API calls.

---

## 2) Alpha test (discard) is the #1 “everything gets darker / thicker / dirtier” footgun

### What DX8 does

DX8 has:

* `ALPHATESTENABLE`
* `ALPHAFUNC` (e.g., GREATER)
* `ALPHAREF` (e.g., 4)

Meaning: **skip fragments below a threshold** before blending.

This is *especially critical* when the blend mode is multiplicative/darken-ish, because even tiny alpha values from filtering/rotation will darken the destination unless discarded.

### What OpenGL/raylib does by default

* No fixed-function alpha test.
* If you just alpha-blend, **low-alpha fringe pixels still contribute**.

### Raylib fix (recommended): alpha-test shader

You need a fragment shader that discards low-alpha pixels **after** applying vertex tint/modulation (matching DX stage output), e.g.:

```glsl
#version 330
in vec2 fragTexCoord;
in vec4 fragColor;
uniform sampler2D texture0;
out vec4 finalColor;

void main() {
    vec4 tex = texture(texture0, fragTexCoord) * fragColor;

    // Example: match DX8 ALPHAFUNC=GREATER ALPHAREF=4
    if (tex.a <= (4.0/255.0)) discard;

    finalColor = tex;
}
```

### Alternate workaround (less ideal): preprocess textures

Clamp tiny alpha to zero on load (and ideally clear RGB where alpha=0 to prevent halos).

### Symptoms that scream “missing alpha test”

* Decals/corpses **darken too much** or have a muddy shadow haze.
* Edges are thicker than the original.
* Rotated/scaled sprites create a “smoky ring” around them.

---

## 3) Blend modes: mapping DX8 blend states to OpenGL (and raylib)

### Core mapping

DX8:

* `ALPHABLENDENABLE`
* `SRCBLEND`, `DESTBLEND`
* `BLENDOP` (usually ADD, sometimes SUBTRACT/MIN/MAX)

OpenGL:

* `glEnable(GL_BLEND)`
* `glBlendFunc(src, dst)` or **glBlendFuncSeparate**
* `glBlendEquation(eq)` or **glBlendEquationSeparate**

### Blend factor mapping cheat table

| D3D8 `D3DBLEND_*` | OpenGL factor                                  |
| ----------------- | ---------------------------------------------- |
| ZERO              | `GL_ZERO`                                      |
| ONE               | `GL_ONE`                                       |
| SRCCOLOR          | `GL_SRC_COLOR`                                 |
| INVSRCCOLOR       | `GL_ONE_MINUS_SRC_COLOR`                       |
| SRCALPHA          | `GL_SRC_ALPHA`                                 |
| INVSRCALPHA       | `GL_ONE_MINUS_SRC_ALPHA`                       |
| DESTCOLOR         | `GL_DST_COLOR`                                 |
| INVDESTCOLOR      | `GL_ONE_MINUS_DST_COLOR`                       |
| DESTALPHA         | `GL_DST_ALPHA`                                 |
| INVDESTALPHA      | `GL_ONE_MINUS_DST_ALPHA`                       |
| SRCALPHASAT       | `GL_SRC_ALPHA_SATURATE`                        |
| BLENDFACTOR       | `GL_CONSTANT_COLOR` *(set via `glBlendColor`)* |
| INVBLENDFACTOR    | `GL_ONE_MINUS_CONSTANT_COLOR`                  |

Blend op mapping:

| D3D8 `D3DBLENDOP_*` | OpenGL equation            |
| ------------------- | -------------------------- |
| ADD                 | `GL_FUNC_ADD`              |
| SUBTRACT            | `GL_FUNC_SUBTRACT`         |
| REVSUBTRACT         | `GL_FUNC_REVERSE_SUBTRACT` |
| MIN                 | `GL_MIN`                   |
| MAX                 | `GL_MAX`                   |

### Two-porting landmines here

#### (A) Separate alpha blending vs “oops I wrecked destination alpha”

DX8-era code often renders into targets that behave like **XRGB** (alpha ignored) or relies on alpha writes being effectively irrelevant.

If you stamp into an RGBA FBO and don’t preserve alpha, you can create:

* unintended alpha buildup
* weird “darken when compositing the RT to screen”
* post-processing masks being wrong

**Fix pattern: preserve destination alpha**
Use either:

* **Color mask:** write RGB but not A
* **Separate blend func:** blend RGB normally but keep alpha as-is

In OpenGL terms, to keep alpha unchanged:

* `glColorMask(true,true,true,false)`
  or
* `glBlendFuncSeparate(srcRGB, dstRGB, GL_ZERO, GL_ONE)` (alpha stays dst)

In raylib/rlgl, look for the “separate” versions (names vary by binding):

* `rlSetBlendFactorsSeparate(srcRGB, dstRGB, srcA, dstA)`
* `rlSetBlendEquationSeparate(eqRGB, eqA)`

#### (B) Premultiplied alpha mismatch (classic halo/dark edge)

DX8 content is usually authored for **straight alpha**.
If you accidentally treat textures as premultiplied (or vice versa), you’ll see:

* dark halos around sprites
* incorrect additive blends
* UI edges look wrong

**Rule of thumb:**

* Straight alpha: use `SRC_ALPHA, ONE_MINUS_SRC_ALPHA`
* Premultiplied: use `ONE, ONE_MINUS_SRC_ALPHA`

If you don’t know: **test with a sprite edge against white and against black**.

---

## 4) Render-to-texture gotchas: upside down, half-pixel shifts, and filtering bleed

### (A) RenderTexture Y-flip (common in raylib)

OpenGL FBO textures are “origin bottom-left” by convention, while many 2D systems are “top-left”.

raylib typically gives you a RenderTexture that you draw with a flipped source rect:

* In C raylib you often do: height negative in `DrawTextureRec`
* In pyray you’ll do the same idea: source rectangle with negative height or adjust UVs

**Symptom:** everything drawn from the RT appears vertically flipped or decals appear offset when sampled.

### (B) Half-pixel / pixel-center differences (DX-era 2D quads)

DX8/9 sprite/quad rendering often involves the infamous **half-pixel offset** to align texels to pixels.

**Symptom:**

* 1px shift
* blurry sprites when they should be crisp
* seams between tiles

**Fix options:**

* Snap sprite positions to integer pixels in screen/RT space.
* Ensure your ortho projection and quad vertices match the pixel center convention you want.
* For atlases: pad/extrude edges by 1–2 pixels to avoid bilinear bleed.

### (C) Bilinear filtering + rotated sprites → low-alpha fringe (ties back to alpha-test)

Even if your texture has hard alpha edges, bilinear sampling produces intermediate alpha values at boundaries after rotation/scale.
DX8 often relied on alpha-test thresholds to kill that fringe.

---

## 5) Coordinate system traps: handedness, winding, depth range

### (A) Left-handed vs right-handed

* DX fixed pipeline is frequently used in **left-handed** space.
* OpenGL conventions are typically **right-handed** (camera looks down -Z).

**Symptoms:**

* models mirrored
* culling “inside out”
* normals/light direction wrong

**Common fixes:**

* Flip Z axis in your view/projection or world transforms (`scale(1,1,-1)`).
* Or keep transforms but change winding/cull mode.

### (B) Front face / culling conventions differ

DX default cull mode historically results in **clockwise** triangles being front-facing in many LH setups.
OpenGL default front face is **CCW**.

**Symptoms:**

* everything disappears when culling enabled
* only backfaces render

**Fix:**

* Swap winding or set front face accordingly (GL_CW vs GL_CCW).
* In raylib, if you’re using its 3D pipeline, you may need to align with raylib’s conventions rather than raw GL.

### (C) Depth range mismatch: DX [0..1] vs GL [-1..1]

If you copy a DX projection matrix verbatim into OpenGL math, depth will be wrong.

**Symptoms:**

* near/far clipping behaves oddly
* depth testing feels inverted or compressed
* z-fighting worse than original

**Fix:**

* Use an OpenGL-correct projection, or apply a depth remap transform.

(If you’re doing mostly 2D decals in an RT, this is less likely to be the main culprit—but it matters a lot for 3D ports.)

---

## 6) Sampler states: filtering, mip bias, wrap modes (and why things look “softer”)

DX8 has per-stage sampler states:

* MINFILTER, MAGFILTER, MIPFILTER
* ADDRESSU/V
* MIPMAPLODBIAS
* MAXANISOTROPY

OpenGL has per-texture (or sampler object) parameters:

* `GL_TEXTURE_MIN_FILTER` (includes mip choice)
* `GL_TEXTURE_MAG_FILTER`
* wrap: `GL_REPEAT`, `GL_CLAMP_TO_EDGE`, etc.

### Footguns

* **Mipmaps generated when DX original had none** → textures look blurrier or “dirtier”.
* **LOD bias not matched** → different sharpness at distance.
* **Wrap vs clamp** mismatch on atlases → edge bleeding.
* **Border color** exists in DX; in GL `CLAMP_TO_BORDER` might not be available on all targets (esp. GLES).

**Debug trick:** force nearest sampling for a frame and see if the artifact disappears (helps distinguish filtering vs blending issues).

---

## 7) Color space and gamma: “why is it darker / lighter than DX?”

DX8-era pipelines typically do blending in **gamma space** (not physically correct), because sRGB framebuffers weren’t standard the way they are now.

OpenGL can be:

* gamma-space (default if you’re not using sRGB textures/FBO)
* or you might accidentally enable sRGB conversions somewhere in your stack

**Symptoms:**

* darkening looks “too strong” or “too weak”
* additive looks wrong
* gradients differ from original

**Rule:** Keep everything consistently gamma-space unless you *intentionally* convert to linear + do proper sRGB output everywhere.

---

## 8) Scissor/viewport origin mismatch (top-left vs bottom-left)

DX scissor/viewport rectangles are typically defined with a **top-left origin**.
OpenGL scissor uses **bottom-left origin**.

**Symptom:**

* clipping region appears in the wrong place
* UI clipping is upside down

**Fix:** convert Y:

* `y_gl = framebufferHeight - (y_dx + height)`

(raylib’s high-level 2D may hide some of this, but anything with rlgl/scissor will bite you.)

---

## 9) Texture stage combiners: “my colors/tints don’t match”

DX8 texture stages can do:

* MODULATE / ADD / ADDSIGNED / SUBTRACT
* blend based on diffuse alpha, texture alpha, TFACTOR, etc.
* per-stage alpha ops separate from color ops

OpenGL/raylib default shader is much simpler:

* usually `final = texture * vertexColor`

**Symptoms:**

* sprites too bright/dim
* vertex-color tinting wrong
* alpha is wrong (especially if alpha is computed by stage ops in DX)

**Fix:** implement a small “FFP emulation shader” for the handful of stage patterns your game uses (often it’s only 2–5 patterns in real codebases).

**Super common missed detail:**
DX’s alpha test is on the **post-stage alpha**, not raw texture alpha.
So your discard must be on the combined result.

---

## 10) “It gets darker over time” = accumulation / queue-clearing / double-stamping

DX code often assumes:

* you stamp once (queue consumed)
* the render target contents persist as ground truth
* you don’t reapply darken passes every frame

OpenGL + raylib wrappers make it easy to accidentally:

* stamp the same decal every frame
* forget to clear a queue
* render the RT into itself (feedback) (less common but catastrophic)

**Symptoms:**

* decals/corpses get progressively darker / blurrier
* artifacts “build up” over seconds

**Fix:**

* Confirm you only stamp once per event.
* Add debug counters: “stamps per frame”, “corpses stamped total”.
* In debug, temporarily clear the RT each frame to see if darkness is accumulation vs state mismatch.

---

## 11) Raylib/pyray-specific footguns and best practices

### (A) Raylib owns a lot of GL state

Raylib sets and resets state around `BeginDrawing/EndDrawing`, `BeginMode2D`, `BeginTextureMode`, etc.

**Rule:** If you touch low-level state (rlgl), do it:

* inside the relevant begin/end block
* and assume you must re-apply it each time

### (B) Built-in blend modes are limited

Raylib’s high-level `BlendMode` enums cover common cases, but DX8 ports often need custom factors/ops.

**Rule:** Use rlgl’s “custom blend factors” calls for parity.

### (C) RenderTexture orientation

Be consistent about flipping only once.
A common double-flip mistake is:

* flip when sampling + flip again when drawing → appears correct for some things but breaks UV math elsewhere.

---

# Fast “Symptom → Cause” lookup

### “Decals/corpses are much darker than original”

* Missing alpha test/discard threshold (low alpha fringe contributes to darken blend)
* Wrong blend factors (e.g., using SRC_ALPHA where DX used ZERO)
* Destination alpha drifting in RGBA RT, then RT composited with blending

### “Edges have dark halos”

* Premultiplied vs straight alpha mismatch
* Atlas bleeding (no padding) + linear filtering
* Missing alpha test threshold

### “Everything is upside down when using RenderTexture”

* FBO origin mismatch (needs Y flip when drawing/sampling)

### “Culling is backwards / geometry disappears”

* Winding order mismatch
* Left-handed vs right-handed mismatch

### “Depth feels wrong”

* DX [0..1] depth vs GL [-1..1] projection mismatch
* Depth func / depth write not mapped correctly

---

# Practical porting workflow that prevents these bugs

1. **Build a “state shadow” layer** that logs *every* DX render state change (from the decompile).
2. For each draw, output a “resolved state packet”:

   * blend enable + factors + op
   * alpha test func/ref
   * depth enable/write/func
   * cull mode + front face
   * texture filter/wrap
3. On the OpenGL side, log what you actually set in rlgl.
4. When visuals drift, compare packets. You’ll usually find a missing state in minutes.
