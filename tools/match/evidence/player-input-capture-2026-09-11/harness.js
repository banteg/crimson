"use strict";

// Execute the production query callbacks and replay packing in Node. Frida's
// callback dispatch, memory reads and event sinks are explicit boundary models.
function createInputHarness(source, options = {}, inputHooks = null) {
  const cut = (start, end, from = 0) => {
    const first = source.indexOf(start, from);
    const last = source.indexOf(end, first + start.length);
    if (first < 0 || last < 0) throw new Error("missing capture source region: " + start);
    return source.slice(first, last);
  };
  const playerCount = options.playerCount ?? 2;
  const bindings = Array.from({ length: playerCount }, (_, i) => ({
    move_forward: 17, move_backward: 31, turn_left: 30, turn_right: 32,
    fire: i === (options.playerIndex ?? 0) ? 104 : 105,
  }));
  const players = options.players ?? Array.from({ length: playerCount }, () => ({
    aim_x: 300, aim_y: 400, aim_heading: 0,
  }));
  const tick = {
    before: { players, input_bindings: { players: bindings, reload: 90 } },
    after: { players, globals: {
      config_movement_schemes: Array(playerCount).fill(2),
      config_aim_schemes: Array(playerCount).fill(options.aimScheme ?? 1),
    } },
    input_player_keys: [],
    fire_by_player: options.projectileCounts ?? [],
  };
  const env = {
    hooks: {}, contexts: {}, queries: [], events: [], errors: [],
    activePlayer: options.playerIndex ?? 0,
    outState: { currentTick: tick, playerCountResolved: playerCount },
  };
  const code = [
    cut("const MOVE_MODE_UNKNOWN", "const CONFIG_PARSE_ERRORS"),
    cut("const FN =", "const DATA ="),
    cut("function failCaptureContract(", "function validateAfterPlayers("),
    cut("function parseHexU32(", "function makeTickContext("),
    cut("function pushInputContext(", "function pushAngleApproachContext("),
    inputHooks ?? cut("  if (CONFIG.enableInputHooks) {", "  if (CONFIG.enableRngHooks) {",
        source.indexOf("function installHooks(")),
  ].join("\n");
  const factory = new Function("env", `
    const CONFIG = { enableInputHooks: true, includeCaller: false };
    const fnPtrs = {}, grimFnPtrs = {};
    const inputContextByTid = env.contexts, outState = env.outState;
    const attachHook = (name, pointer, handlers) => { env.hooks[name] = handlers; };
    const runtimeToStatic = address => address;
    const toHex = (value, digits) => "0x" + value.toString(16).padStart(digits, "0");
    const formatCaller = address => toHex(address, 8);
    const maybeBacktrace = () => null;
    const readDataI32 = name => {
      if (name !== "render_overlay_player_index") throw new Error(name);
      return env.activePlayer;
    };
    const readDataU32 = () => 0;
    const captureNumber = value => Math.fround(value);
    const registerInputQuery = (...args) => env.queries.push(args);
    const emitRawEvent = event => env.events.push(event);
    const emitCaptureContractError = error => env.errors.push(error);
    ${code}
    for (let i = 0; i < outState.playerCountResolved; ++i)
      ensurePlayerKeyState(outState.currentTick, i);
    return { replayInputIntentFromTick, replayInputsFromIntentRows };
  `);
  const production = factory(env);
  function begin(name, caller, key, threadId = 1) {
    const invocation = { threadId, returnAddress: caller, context: {} };
    env.hooks[name].onEnter.call(invocation, [{ toInt32: () => key }]);
    return { name, invocation };
  }
  function leave(call, result) {
    env.hooks[call.name].onLeave.call(call.invocation, { toInt32: () => result | 0 });
  }
  function query(event) {
    env.activePlayer = event.player_index ?? options.playerIndex ?? 0;
    const call = begin(event.name, event.caller, event.key, event.thread_id ?? 1);
    if (event.name === "grim_is_key_active" && event.key <= 0xff) {
      // The original keyboard arm calls grim_is_key_down, returning at this RVA.
      const inner = begin("grim_is_key_down", 0x100071a2, event.key, event.thread_id ?? 1);
      leave(inner, event.result);
    }
    leave(call, event.result);
  }
  function snapshot() {
    const intent = production.replayInputIntentFromTick(tick);
    return {
      keys: tick.input_player_keys, intent,
      inputs: production.replayInputsFromIntentRows(intent, "intent"),
      queries: env.queries, events: env.events, errors: env.errors,
      contexts: env.contexts,
    };
  }
  return { env, tick, begin, leave, query, snapshot };
}

module.exports = { createInputHarness };

if (require.main === module) {
  const fs = require("node:fs");
  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  const source = fs.readFileSync(request.source, "utf8");
  const inputHooks = request.input_hooks ? fs.readFileSync(request.input_hooks, "utf8") : null;
  const results = request.cases.map(row => {
    const harness = createInputHarness(source, row.options, inputHooks);
    for (const event of row.events) harness.query(event);
    return { name: row.name, ...harness.snapshot() };
  });
  process.stdout.write(JSON.stringify(results));
}
