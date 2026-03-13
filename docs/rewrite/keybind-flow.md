---
tags:
  - rewrite
  - controls
---

# Keybind Flow

This note describes the current keybind flow in the Python port after the
config-model cleanup.

The important conclusions are:

- `crimson.cfg` stores original Grim input codes, not raylib enums.
- `src/crimson/input_codes.py` is the only Grim-code to raylib translator.
- `src/grim/config.py` owns the wire-layout bridge and default/canonical write
  policy.
- Runtime code reads grouped semantic controls directly.
- The controls menu owns the only remaining UI-specific rebind mapping.

The companion structure diagram lives in `keybind-flow.d2`.

## Code Domains

There are four domains involved:

1. Wire layout in `src/grim/config.py`
   - fixed `crimson.cfg` blob
   - original field order and offsets

2. Semantic config model in `src/grim/config.py`
   - `CrimsonControlsConfig`
   - `CrimsonPlayerControls`
   - grouped Grim input codes such as `move_codes`, `fire_code`,
     `keyboard_aim_codes`, `aim_axis_codes`, and `move_axis_codes`

3. Original Grim input-code domain in `src/crimson/input_codes.py`
   - keyboard DIK-style codes below `0x100`
   - mouse buttons at `0x100+`
   - joystick buttons, POV directions, and axes in the `0x11f+` range

4. Backend input domain in raylib
   - `rl.KeyboardKey`
   - `rl.MouseButton`
   - `rl.GamepadButton`
   - `rl.GamepadAxis`

The config model should stay entirely in domains 1 and 2.
The backend translator should stay entirely in domains 3 and 4.

## What Is Stored On Disk

The wire layout is defined by `CRIMSON_CFG_STRUCT` in `src/grim/config.py`.

For controls:

- P1/P2 live in `keybinds_p1_p2`
- P3/P4 live in `extended_keybinds_p3_p4`
- the P3/P4 blocks are our port extension inside the original reserved gap

Each raw per-player bind block is represented in the wire schema as:

- `move_forward`
- `move_backward`
- `turn_left`
- `turn_right`
- `fire`
- `reserved_keys[2]`
- `aim_left`
- `aim_right`
- `axis_aim_y`
- `axis_aim_x`
- `axis_move_y`
- `axis_move_x`
- `padding[3]`

That shape is good for the wire codec because it stays close to the original
layout and reverse-engineering field names.

## What The Semantic Model Stores

`decode_crimson_cfg(...)` maps each raw bind block into `CrimsonPlayerControls`.

That semantic model stores only the bindings the port actually uses:

- `movement`
- `aim_scheme`
- `show_direction_arrow`
- `move_codes`
- `fire_code`
- `keyboard_aim_codes`
- `aim_axis_codes`
- `move_axis_codes`

`CrimsonControlsConfig` then adds:

- `players[4]`
- `pick_perk_code`
- `reload_code`

This is the current stable semantic boundary.

It is intentionally not a generic 16-slot tuple API, but it also does not try to
invent fake higher-level meanings for all raw slots. Unused raw slots remain a
wire concern only and are written canonically from defaults.

## How The Controls Menu Works

The controls menu no longer works in raw slot ids or string field names.

`controls_rebind_plan(...)` in `src/crimson/screens/panels/controls_labels.py`
returns `RebindRowSpec` values that contain:

- a visible label
- a typed `RebindTarget`
- an optional tuple index
- an `axis` flag

The target describes exactly what is being edited:

- `PLAYER_MOVE_CODES`
- `PLAYER_FIRE_CODE`
- `PLAYER_KEYBOARD_AIM_CODES`
- `PLAYER_AIM_AXIS_CODES`
- `PLAYER_MOVE_AXIS_CODES`
- `GLOBAL_PICK_PERK_CODE`
- `GLOBAL_RELOAD_CODE`

`ControlsMenuView` in `src/crimson/screens/panels/controls.py` then:

1. builds the visible row plan from `movement` and `aim_scheme`
2. reads the selected value through an explicit `match` on `RebindTarget`
3. captures a new Grim input code via `capture_first_pressed_input_code(...)`
4. writes the updated Grim code back through the same typed target
5. calls `config.save()` on close

Important point:

- rebinding stores original Grim-style codes in config
- rebinding does not store raylib enums

That is the correct boundary.

## Runtime Input Flow

The main gameplay consumer is `LocalInputInterpreter` in
`src/crimson/local_input.py`.

Its input path is:

1. read grouped per-player controls from config
2. select which codes matter for the current `movement` and `aim_scheme`
3. pass those Grim codes to `input_code_is_down(...)`,
   `input_code_is_pressed(...)`, or `input_axis_value(...)`
4. let `src/crimson/input_codes.py` translate them to raylib polling
5. build `PlayerInput`

The movement and aim schemes decide how the grouped binds are interpreted:

- `MovementControlType.STATIC`
  - uses `move_codes` as Up, Down, Left, Right

- `MovementControlType.RELATIVE`
  - uses the same `move_codes` as Forward, Backward, Turn left, Turn right

- `MovementControlType.DUAL_ACTION_PAD`
  - uses `move_axis_codes`

- `MovementControlType.MOUSE_POINT_CLICK`
  - uses global `reload_code` as the "move to cursor" trigger

- `AimScheme.KEYBOARD`
  - uses `keyboard_aim_codes`

- `AimScheme.DUAL_ACTION_PAD`
  - uses `aim_axis_codes`

- `AimScheme.JOYSTICK`
  - does not use stored keyboard aim binds
  - uses hardcoded POV input codes `0x133` / `0x134`

- `AimScheme.MOUSE`
  - aims directly from mouse world position

- `AimScheme.MOUSE_RELATIVE`
  - aims from mouse delta relative to screen center

- `AimScheme.COMPUTER`
  - ignores player aim binds and computes aim internally

This is why grouped semantic fields are a better fit than per-slot fake names
like `move_forward_code` or a generic 16-slot tuple.

## Other Keybind Consumers

Outside `LocalInputInterpreter`, there are only a few narrow consumers:

- `src/crimson/modes/tutorial_mode.py`
  - directly reads `move_codes`, `fire_code`, and `reload_code`

- `src/crimson/modes/components/perk_prompt_controller.py`
  - directly reads player fire codes plus `pick_perk_code`

- `src/crimson/ui/text_input.py`
  - checks the first five gameplay controls: the movement quartet plus `fire`

These direct reads are simple and do not justify a generic config-keybind helper
layer.

## Grim Code To Raylib Translation

`src/crimson/input_codes.py` is the real translation layer.

It contains:

- keyboard DIK-style mapping via `_DIK_TO_RL_KEY`
- mouse-button mapping via `_MOUSE_CODE_TO_BUTTON`
- joystick button mapping via `_JOYS_BUTTON_CODES`
- axis mapping via `_AXIS_CODE_TO_AXIS`
- older RIM-device mappings via `_RIM_AXIS_CODES` and `_RIM_BUTTON_CODES`

Two directions matter:

1. Stored config code -> raylib poll
   - `input_code_is_down(...)`
   - `input_code_is_pressed(...)`
   - `input_axis_value(...)`

2. Raylib event -> stored config code
   - `capture_first_pressed_input_code(...)`

That file should remain the only place that knows how a stored Grim code maps
onto current backend input.

## Defaults And Canonicalization

There are two important config-side policies:

1. Decode-time backfill for zeroed bind blocks
   - if a raw player bind block is fully zeroed, `decode_crimson_cfg(...)`
     substitutes that player's default bindings

2. Encode-time canonicalization for wire-only fields
   - unused raw bind slots are written from canonical per-player defaults
   - reserved bytes are written canonically by the config bridge

Runtime code does not have a `config is None` fallback anymore.
Gameplay code is expected to receive a real `CrimsonConfig`.

## Current Assessment

The structure is now:

- storage is original Grim layout
- semantic config stores grouped Grim input codes
- the controls menu edits those grouped controls through typed UI-local targets
- runtime translation is original Grim code -> raylib
- runtime/gameplay code reads grouped controls directly

That is the right mental model.

The remaining complexity is mostly inherent:

- the wire format is old and irregular
- movement and aim schemes reinterpret the same stored control groups
- the controls menu still has UI-specific row planning logic

What should not come back is:

- a generic 16-slot keybind API
- config-aware helper wrappers in `input_codes.py`
- stringly typed rebind field access
- a second runtime cache layer for bindings
