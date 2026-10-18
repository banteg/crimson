// A run's timeline for its page, recorded while verification replays it: crimson-core's probe
// (crimson-core/host/api.h PortableProbe) after every tick, kept once a second, the path ten times a second, and the
// moments things changed. Perk and weapon ids are the game's (web/src/perks.json, web/src/weapons.json).

import { PLAYER_EFFECTS, type PlayerTimeline, type Timeline } from "./api-types";

export const PROBE_BYTES = 136;
// PortableProbePlayer: each player's x, y, health, weapon and own timers.
const PLAYER_AT = 80;
const PLAYER_BYTES = 28;
// The probe's timers in the timeline's order, each at its offset in the probe or, for a player's own (PLAYER_EFFECTS),
// in their part.
const EFFECTS: [name: string, at: number][] = [
  ["Double Experience", 60],
  ["Weapon Power Up", 64],
  ["Fire Bullets", 16],
  ["Freeze", 68],
  ["Reflex Boost", 72],
  ["Energizer", 76],
  ["Shield", 20],
  ["Speed", 24],
];
const TICKS_PER_SAMPLE = 60;
const TICKS_PER_POINT = 6;
// A timer that lapses for less than this between points continues the same span.
const SPAN_GAP_S = 0.25;

// Player `player`'s part of the probe.
const playerAt = (player: number) => PLAYER_AT + player * PLAYER_BYTES;

// Extends the effect's last span to `t`, or starts one.
function active(effects: Timeline["effects"], name: string, t: number): void {
  const spans = (effects[name] ??= []);
  const span = spans.at(-1);
  if (span && span[1] >= t - SPAN_GAP_S) span[1] = t;
  else spans.push([t, t]);
}

const sampledHealth = (health: number) => Math.round(Math.max(0, health) * 10) / 10;

// One co-op player's own record. A downed player (health 0 or less) can be healed back up while their health stays
// above the MediKit's floor, so only their last fall that lasts to the run's end is their death: the path keeps its
// point at each fall and ends at that one, and their own bonuses count only while they stand.
class PlayerRecorder {
  private weapon = -1;
  // When the player last went down, while they still are.
  private down: number | null = null;
  readonly line: PlayerTimeline = { health: [], path: [], weapons: [], effects: {}, death_s: null };

  constructor(private readonly at: number) {}

  record(probe: DataView, t: number, point: boolean): void {
    const f32 = (offset: number) => probe.getFloat32(this.at + offset, true);
    const weapon = probe.getInt32(this.at + 12, true);
    if (weapon !== this.weapon) this.line.weapons.push({ t, id: (this.weapon = weapon) });
    const standing = f32(8) > 0;
    const fell = !standing && this.down === null;
    this.down = standing ? null : (this.down ?? t);
    if (point || fell) this.line.path.push([t, Math.round(f32(0)), Math.round(f32(4))]);
    if (point && standing) for (const [name, offset] of EFFECTS) if (PLAYER_EFFECTS.includes(name) && f32(offset) > 0) active(this.line.effects, name, t);
  }

  sample(probe: DataView): void {
    this.line.health.push(sampledHealth(probe.getFloat32(this.at + 8, true)));
  }

  finish(): void {
    const death = (this.line.death_s = this.down);
    if (death !== null) this.line.path = this.line.path.filter(([t]) => t <= death);
  }
}

export class TimelineRecorder {
  private tick = 0;
  private weapon = -1;
  private level = -1;
  private nukes = 0;
  private last: DataView | null = null;
  private readonly timeline: Timeline;
  private readonly players: PlayerRecorder[];

  // The run's player count: a co-op run's timeline records each player's own too.
  constructor(seed: number, players: number) {
    this.timeline = { seed, duration_s: 0, samples: [], path: [], weapons: [], perks: [], levels: [], nukes: [], effects: {} };
    this.players = players > 1 ? Array.from({ length: players }, (_, player) => new PlayerRecorder(playerAt(player))) : [];
    if (this.players.length) this.timeline.players = this.players.map((player) => player.line);
  }

  record(probe: DataView): void {
    const f32 = (at: number) => probe.getFloat32(at, true);
    const i32 = (at: number) => probe.getInt32(at, true);
    const one = playerAt(0);
    const t = i32(4) / 1000;
    const line = this.timeline;
    const weapon = i32(one + 12);
    if (weapon !== this.weapon) line.weapons.push({ t, id: (this.weapon = weapon) });
    const level = i32(12);
    if (this.level !== -1 && level > this.level) line.levels.push({ t, level });
    this.level = level;
    for (let i = 0; i < i32(24); i++) line.perks.push({ t, id: i32(28 + i * 4) });
    for (; this.nukes < i32(20); this.nukes++) line.nukes.push(t);
    const point = this.tick % TICKS_PER_POINT === 0;
    if (point) {
      line.path.push([t, Math.round(f32(one)), Math.round(f32(one + 4))]);
      for (const [name, at] of EFFECTS) if (f32(PLAYER_EFFECTS.includes(name) ? one + at : at) > 0) active(line.effects, name, t);
    }
    for (const player of this.players) player.record(probe, t, point);
    if (this.tick % TICKS_PER_SAMPLE === 0) this.sample(probe);
    this.last = probe;
    this.tick++;
  }

  finish(): Timeline {
    // The final tick is always a sample, so the curves end where the run did.
    if ((this.tick - 1) % TICKS_PER_SAMPLE !== 0 && this.last) this.sample(this.last);
    this.timeline.duration_s = this.timeline.samples.at(-1)?.[0] ?? 0;
    for (const player of this.players) player.finish();
    return this.timeline;
  }

  private sample(probe: DataView): void {
    this.timeline.samples.push([
      probe.getInt32(4, true) / 1000,
      probe.getInt32(8, true),
      probe.getInt32(12, true),
      sampledHealth(probe.getFloat32(playerAt(0) + 8, true)),
      probe.getInt32(16, true),
      Math.round(probe.getFloat32(0, true)),
    ]);
    for (const player of this.players) player.sample(probe);
  }
}
