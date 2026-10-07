// Verification: replay the run through crimson-core's WASM build, check every tick against the ranked controls and
// aim bound, and compare the derived result with the claimed one (docs/rewrite/ranked-rules.md).
//
// The result is derived from the core's state as crimson-core/checks/gate.py derives it; the per-tick check is
// src/crimson/replay/ranked.py's RankedTickMonitor. A verified run also gets its page's timeline (src/timeline.ts).

import coreModule from "../../crimson-core/build/wasm/core.wasm";
import schema from "../../crimson-core/schema.json";
import type { Timeline } from "./api-types";
import type { Env } from "./http";
import { Flags, type Replay, type RunResult } from "./replay";
import { PROBE_BYTES, TimelineRecorder } from "./timeline";
import { CONFIG_BYTES, TICK_BYTES } from "./transport";

interface Core {
  memory: WebAssembly.Memory;
  _initialize(): void;
  portable_config(): number;
  portable_input(): number;
  portable_commands(): number;
  portable_output(): number;
  portable_init(seed: number, mode: number, major: number, minor: number): number;
  portable_step_many(count: number): number;
  portable_snapshot(): number;
  portable_player_x(): number;
  portable_player_y(): number;
  portable_player_health(): number;
  portable_shake_x(): number;
  portable_shake_y(): number;
  portable_probe(): number;
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
const VIEW_W = 1024;
const VIEW_H = 768;
const TERRAIN_SIZE = 1024;
const PAD_AIM_REACH = 96 + 42;
const AIM_SLACK = 0.01;
const HUMAN_MOVEMENT = new Set([1, 2, 3, 4]);
const HUMAN_AIM = new Set([0, 1, 2, 3, 4]);
const AIM_MOUSE = 0;
const AIM_DUAL_ACTION_PAD = 4;
const MOVE_POINT_CLICK = 4;

export type Verdict = { ok: true; timeline: Timeline } | { ok: false; reason: string };

export async function verifyRun(_env: Env, replay: Replay, transport: Uint8Array): Promise<Verdict> {
  return simulate(replay, transport);
}

function simulate(replay: Replay, transport: Uint8Array): Verdict {
  const c = core();
  const view = new DataView(transport.buffer, transport.byteOffset, transport.byteLength);
  new Uint8Array(c.memory.buffer, c.portable_config(), CONFIG_BYTES).set(transport.subarray(0, CONFIG_BYTES));
  if (!c.portable_init(...([0, 4, 8, 12].map((at) => view.getUint32(at, true)) as [number, number, number, number])))
    return { ok: false, reason: "the core refused the run's settings" };

  const monitor = new TickMonitor();
  monitor.updateCamera(c);
  const recorder = new TimelineRecorder(replay.run.seed);
  let at = CONFIG_BYTES;
  for (let tick = 0; tick < replay.ticks.length; tick++) {
    const reason = monitor.check(replay.ticks[tick]!.inputs[0]!);
    if (reason) return { ok: false, reason: `tick ${tick}: ${reason}` };
    const count = view.getUint32(at + 20, true);
    new Uint8Array(c.memory.buffer, c.portable_input(), 20).set(transport.subarray(at, at + 20));
    new Uint8Array(c.memory.buffer, c.portable_commands(), count * 8).set(transport.subarray(at + TICK_BYTES, at + TICK_BYTES + count * 8));
    if (!c.portable_step_many(count)) return { ok: false, reason: `tick ${tick}: an illegal command or a tick past the run's end` };
    at += TICK_BYTES + count * 8;
    monitor.updateCamera(c);
    recorder.record(new DataView(c.memory.buffer, c.portable_probe(), PROBE_BYTES));
  }

  if (c.portable_snapshot() !== fieldIndex.size) throw new Error("crimson-core snapshot schema mismatch");
  const derived = deriveResult(new DataView(c.memory.buffer, c.portable_output(), fieldIndex.size * 4), replay.run.game_mode_id);
  const mismatches = resultMismatches(replay.result, derived);
  return mismatches.length
    ? { ok: false, reason: `the claimed result differs in ${mismatches.join(", ")}` }
    : { ok: true, timeline: recorder.finish() };
}

class TickMonitor {
  private camera: { x: number; y: number } | null = null;
  private moveTarget: { x: number; y: number } | null = null;

  updateCamera(c: Core): void {
    let camera = this.camera;
    if (c.portable_player_health() > 0) camera = { x: VIEW_W * 0.5 - c.portable_player_x(), y: VIEW_H * 0.5 - c.portable_player_y() };
    if (camera === null) return;
    const x = camera.x + c.portable_shake_x();
    const y = camera.y + c.portable_shake_y();
    this.camera = {
      x: Math.max(Math.min(x, -1), VIEW_W - TERRAIN_SIZE),
      y: Math.max(Math.min(y, -1), VIEW_H - TERRAIN_SIZE),
    };
  }

  check([moveX, moveY, aimX, aimY, flags]: [number, number, number, number, number]): string | null {
    const moveKeys = Boolean(flags & Flags.MOVE_KEYS_PRESENT);
    const moveMode = flags & Flags.MOVE_MODE_PRESENT ? (flags >>> Flags.MOVE_MODE_SHIFT) & Flags.MASK3 : moveKeys ? 2 : 3;
    const aimRaw = (flags >>> Flags.AIM_SCHEME_SHIFT) & Flags.MASK3;
    const aimScheme = flags & Flags.AIM_SCHEME_PRESENT ? (aimRaw === Flags.MASK3 ? -1 : aimRaw) : AIM_MOUSE;
    if (!HUMAN_MOVEMENT.has(moveMode) || !HUMAN_AIM.has(aimScheme)) return "computer or unknown controls";
    const camera = this.camera!;
    if (aimScheme === AIM_MOUSE && !inView(aimX + camera.x, aimY + camera.y)) return "aim outside the 1024x768 view";
    if (aimScheme === AIM_DUAL_ACTION_PAD && Math.hypot(aimX, aimY) > PAD_AIM_REACH + AIM_SLACK) return "pad aim beyond its reach";
    if (moveMode === MOVE_POINT_CLICK) {
      const target = moveX === -1 ? null : { x: moveX, y: moveY };
      const changed = target !== null && (this.moveTarget === null || target.x !== this.moveTarget.x || target.y !== this.moveTarget.y);
      if (changed && !inView(target.x + camera.x, target.y + camera.y)) return "move target outside the 1024x768 view";
      this.moveTarget = target;
    }
    return null;
  }
}

function inView(x: number, y: number): boolean {
  return -AIM_SLACK <= x && x <= VIEW_W + AIM_SLACK && -AIM_SLACK <= y && y <= VIEW_H + AIM_SLACK;
}

function deriveResult(snapshot: DataView, mode: number): RunResult {
  const u32 = (name: string) => snapshot.getUint32(fieldIndex.get(name)! * 4, true);
  const i32 = (name: string) => snapshot.getInt32(fieldIndex.get(name)! * 4, true);
  const f32 = (name: string) => snapshot.getFloat32(fieldIndex.get(name)! * 4, true);
  const outcome = TERMINAL_OUTCOMES[u32("globals.game_state_pending")] ?? "incomplete";
  const elapsed = i32(mode === 3 ? "globals.quest_spawn_timeline" : "globals.run_elapsed_ms");
  const health = f32("players[0].health");
  const pending = u32("globals.perk_pending_count");
  const fired = Math.max(0, i32("globals.highscore_record_shots_fired"));
  const hit = Math.max(0, Math.min(i32("globals.highscore_record_shots_hit"), fired));
  // src/crimson/weapon_runtime/assign.py most_used_weapon_id_for_player over the 53 tracked slots.
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
    players: [{ experience: u32("players[0].experience"), health, most_used_weapon_id: best }],
  };
}

// src/crimson/quests/results.py compute_quest_final_time for one player: the truncated health times 50 is exact.
function questFinalMs(base: number, health: number, pending: number): number {
  const final = base - Math.trunc(health) * 50 - pending * 1000;
  return final === 0 ? 1 : final;
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
