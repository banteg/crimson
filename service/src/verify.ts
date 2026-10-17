// Verification: replay the run through crimson-core's WASM build, check every tick against the ranked controls and
// aim bound, and compare the derived result with the claimed one (docs/rewrite/ranked-rules.md).
//
// The result is derived from the core's state as crimson-core/checks/gate.py derives it; the per-tick check is
// src/crimson/replay/ranked.py's RankedTickMonitor. A verified run also gets its page's timeline (src/timeline.ts).

import coreModule from "../../crimson-core/build/wasm/core.wasm";
import schema from "../../crimson-core/schema.json";
import type { Timeline } from "./api-types";
import type { Env } from "./http";
import { type Replay, type RunResult, tickControls } from "./replay";
import { mergeSignals, type Signals, SignalMeter } from "./signals";
import { questFinalMs } from "./quest-time";
import { PROBE_BYTES, TimelineRecorder } from "./timeline";
import { BAKES_BYTES } from "./ground";
import { CONFIG_BYTES, INPUT_BYTES, QUEST_BYTES, tickBytes } from "./transport";

interface Core {
  memory: WebAssembly.Memory;
  _initialize(): void;
  portable_config(): number;
  portable_quest(): number;
  portable_input(): number;
  portable_commands(): number;
  portable_output(): number;
  portable_init(seed: number, mode: number, major: number, minor: number): number;
  portable_step_many(count: number): number;
  portable_refusal(): number;
  portable_snapshot(): number;
  portable_player_x(player: number): number;
  portable_player_y(player: number): number;
  portable_player_health(player: number): number;
  portable_probe(): number;
  portable_nearest_creature(x: number, y: number): number;
  portable_bakes(): number;
}

// One instance per isolate. Nothing awaits between init and the final snapshot, so requests never interleave
// simulation state.
let instance: Core | null = null;
function core(): Core {
  if (instance === null) {
    instance = new WebAssembly.Instance(coreModule, {}).exports as unknown as Core;
    instance._initialize();
  }
  return instance;
}

const fieldIndex = new Map<string, number>();
for (const group of schema as { name: string; count: number; fields: string[] }[])
  for (let i = 0; i < group.count; i++)
    for (const field of group.fields) fieldIndex.set(`${group.name}${group.count > 1 ? `[${i}]` : ""}.${field}`, fieldIndex.size);

const GameState = { GAME_OVER: 0x07, QUEST_RESULTS: 0x08, QUEST_FAILED: 0x0c } as const;
const TERMINAL_OUTCOMES: Record<number, string> = {
  [GameState.GAME_OVER]: "death",
  [GameState.QUEST_FAILED]: "death",
  [GameState.QUEST_RESULTS]: "quest_completed",
};
const WEAPON_USAGE_SLOTS = 53;

// The ranked view (src/crimson/replay/ranked.py).
export const VIEW_W = 1024;
export const VIEW_H = 768;
const TERRAIN_SIZE = 1024;
const PAD_AIM_REACH = 96 + 42;
const AIM_SLACK = 0.01;
const VIEW_SLACK = 96;
const HUMAN_MOVEMENT = new Set([1, 2, 3, 4]);
const HUMAN_AIM = new Set([0, 1, 2, 3, 4]);
const AIM_MOUSE = 0;
const AIM_DUAL_ACTION_PAD = 4;
const MOVE_POINT_CLICK = 4;

// The signals cover the ticks replayed, up to a refused one.
export type Verdict = ({ ok: true; timeline: Timeline } | { ok: false; reason: string }) & { signals: Signals };

// `bake` sees what each tick bakes into the terrain (PortableBakes in crimson-core/host/api.h), for the run's ground.
export async function verifyRun(_env: Env, replay: Replay, transport: Uint8Array, bake?: (bakes: DataView) => void): Promise<Verdict> {
  return simulate(replay, transport, bake);
}

function simulate(replay: Replay, transport: Uint8Array, bake?: (bakes: DataView) => void): Verdict {
  const c = core();
  const view = new DataView(transport.buffer, transport.byteOffset, transport.byteLength);
  const players = replay.run.player_count;
  const meters = Array.from({ length: players }, () => new SignalMeter());
  const signals = () => mergeSignals(meters.map((meter) => meter.finish()));
  const refused = (reason: string): Verdict => ({ ok: false, reason, signals: signals() });
  const custom = replay.run.custom_quest !== null;
  new Uint8Array(c.memory.buffer, c.portable_config(), CONFIG_BYTES).set(transport.subarray(0, CONFIG_BYTES));
  if (custom)
    new Uint8Array(c.memory.buffer, c.portable_quest(), QUEST_BYTES).set(transport.subarray(CONFIG_BYTES, CONFIG_BYTES + QUEST_BYTES));
  if (!c.portable_init(...([0, 4, 8, 12].map((at) => view.getUint32(at, true)) as [number, number, number, number])))
    return refused("the core refused the run's settings");

  const monitor = new TickMonitor(players);
  monitor.updateCamera(c);
  const recorder = new TimelineRecorder(replay.run.seed);
  const nearest = (x: number, y: number) => c.portable_nearest_creature(x, y);
  const inputs = players * INPUT_BYTES;
  let at = CONFIG_BYTES + (custom ? QUEST_BYTES : 0);
  for (let tick = 0; tick < replay.ticks.length; tick++) {
    for (let player = 0; player < players; player++) {
      const input = replay.ticks.input(tick, player);
      const state = { x: c.portable_player_x(player), y: c.portable_player_y(player), alive: c.portable_player_health(player) > 0 };
      meters[player]!.record(input, state, monitor.camera!, nearest);
      const reason = monitor.check(player, input);
      if (reason) return refused(`tick ${tick}: ${players > 1 ? `player ${player + 1}'s ` : ""}${reason}`);
    }
    const count = view.getUint32(at + inputs, true);
    const commands = at + tickBytes(players);
    new Uint8Array(c.memory.buffer, c.portable_input(), inputs).set(transport.subarray(at, at + inputs));
    new Uint8Array(c.memory.buffer, c.portable_commands(), count * 8).set(transport.subarray(commands, commands + count * 8));
    if (!c.portable_step_many(count)) return refused(`tick ${tick}: ${refusal(c)}`);
    at = commands + count * 8;
    monitor.updateCamera(c);
    recorder.record(new DataView(c.memory.buffer, c.portable_probe(), PROBE_BYTES));
    bake?.(new DataView(c.memory.buffer, c.portable_bakes(), BAKES_BYTES));
  }

  if (c.portable_snapshot() !== fieldIndex.size) throw new Error("crimson-core snapshot schema mismatch");
  const derived = deriveResult(new DataView(c.memory.buffer, c.portable_output(), fieldIndex.size * 4), replay.run.game_mode_id, players);
  const mismatches = resultMismatches(replay.result, derived);
  return mismatches.length
    ? refused(`the claimed result differs in ${mismatches.join(", ")}`)
    : { ok: true, timeline: recorder.finish(), signals: signals() };
}

// Why the core refused its last tick (`portable_refusal` in crimson-core/host/api.h).
function refusal(c: Core): string {
  const bytes = new Uint8Array(c.memory.buffer, c.portable_refusal());
  return new TextDecoder().decode(bytes.subarray(0, bytes.indexOf(0)));
}

// src/crimson/replay/ranked.py RankedTickMonitor: every player's controls and aim against one view.
export class TickMonitor {
  // The ranked view's camera the last tick left: screen = world + camera.
  camera: { x: number; y: number } | null = null;
  // Each player's point-click target.
  private moveTargets: ({ x: number; y: number } | null)[] = [];

  constructor(private readonly players: number) {}

  // The camera follows the game's (src/crimson/camera.py camera_update_for_players): player one, or in co-op the
  // living players' midpoint, kept where it was while nobody lives.
  updateCamera(c: Pick<Core, "portable_player_x" | "portable_player_y" | "portable_player_health">): void {
    const focus = { x: 0, y: 0 };
    let alive = 0;
    for (let player = 0; player < this.players; player++) {
      if (this.players > 1 && !(c.portable_player_health(player) > 0)) continue;
      focus.x += c.portable_player_x(player);
      focus.y += c.portable_player_y(player);
      alive++;
    }
    if (!alive) return;
    this.camera = {
      x: Math.max(Math.min(VIEW_W * 0.5 - focus.x / alive, -1), VIEW_W - TERRAIN_SIZE),
      y: Math.max(Math.min(VIEW_H * 0.5 - focus.y / alive, -1), VIEW_H - TERRAIN_SIZE),
    };
  }

  check(player: number, [moveX, moveY, aimX, aimY, flags]: [number, number, number, number, number]): string | null {
    const { moveMode, aimScheme } = tickControls(flags);
    if (!HUMAN_MOVEMENT.has(moveMode) || !HUMAN_AIM.has(aimScheme)) return "computer or unknown controls";
    const camera = this.camera!;
    if (aimScheme === AIM_MOUSE && !inView(aimX + camera.x, aimY + camera.y)) return "aim outside the 1024x768 view";
    if (aimScheme === AIM_DUAL_ACTION_PAD && Math.hypot(aimX, aimY) > PAD_AIM_REACH + AIM_SLACK) return "pad aim beyond its reach";
    if (moveMode === MOVE_POINT_CLICK) {
      const target = moveX === -1 ? null : { x: moveX, y: moveY };
      const last = this.moveTargets[player] ?? null;
      const changed = target !== null && (last === null || target.x !== last.x || target.y !== last.y);
      if (changed && !inView(target.x + camera.x, target.y + camera.y)) return "move target outside the 1024x768 view";
      this.moveTargets[player] = target;
    }
    return null;
  }
}

function inView(x: number, y: number): boolean {
  return -VIEW_SLACK <= x && x <= VIEW_W + VIEW_SLACK && -VIEW_SLACK <= y && y <= VIEW_H + VIEW_SLACK;
}

export function deriveResult(snapshot: DataView, mode: number, players: number): RunResult {
  const u32 = (name: string) => snapshot.getUint32(fieldIndex.get(name)! * 4, true);
  const i32 = (name: string) => snapshot.getInt32(fieldIndex.get(name)! * 4, true);
  const f32 = (name: string) => snapshot.getFloat32(fieldIndex.get(name)! * 4, true);
  const outcome = TERMINAL_OUTCOMES[u32("globals.game_state_pending")] ?? "incomplete";
  const elapsed = i32(mode === 3 ? "globals.quest_spawn_timeline" : "globals.run_elapsed_ms");
  const health = Array.from({ length: players }, (_, i) => f32(`players[${i}].health`));
  const pending = u32("globals.perk_pending_count");
  const fired = Math.max(0, i32("globals.highscore_record_shots_fired"));
  const hit = Math.max(0, Math.min(i32("globals.highscore_record_shots_hit"), fired));
  // src/crimson/weapon_runtime/assign.py most_used_weapon_id_for_player over the 53 slots the core's snapshot holds,
  // as its replay_result does. Python and the original scan all 64, but only player one's weapon accrues time, and
  // drops and stock quests hand out weapons up to 33, so the rest stay zero; only a custom quest starting with the
  // Nuke Launcher (53) could tell them apart. The table is shared: every player's most used weapon is the same.
  let best = 1;
  for (let weapon = 2; weapon < WEAPON_USAGE_SLOTS; weapon++)
    if (i32(`globals.weapon_usage_time[${weapon}]`) > i32(`globals.weapon_usage_time[${best}]`)) best = weapon;
  return {
    outcome,
    elapsed_ms: elapsed,
    kills: u32("globals.creature_kill_count"),
    shots_fired: fired,
    shots_hit: hit,
    rng_state: u32("globals.rng"),
    pending_perks: pending,
    quest_final_ms: outcome === "quest_completed" ? questFinalMs(elapsed, health, pending) : null,
    // Experience is shared on player one; player two's stays 0.
    players: health.map((h, i) => ({ experience: u32(`players[${i}].experience`), health: h, most_used_weapon_id: best })),
  };
}


function resultMismatches(claimed: RunResult, derived: RunResult): string[] {
  const fields = ["outcome", "elapsed_ms", "kills", "shots_fired", "shots_hit", "rng_state", "pending_perks", "quest_final_ms"] as const;
  const mismatches: string[] = fields.filter((field) => claimed[field] !== derived[field]);
  if (claimed.players.length !== derived.players.length) return [...mismatches, "players"];
  claimed.players.forEach((player, i) => {
    for (const field of ["experience", "health", "most_used_weapon_id"] as const)
      if (player[field] !== derived.players[i]![field]) mismatches.push(`players[${i}].${field}`);
  });
  return mismatches;
}
