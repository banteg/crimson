// A run's timeline for its page, recorded while verification replays it: crimson-core's probe
// (crimson-core/host/api.h PortableProbe) after every tick, kept once a second, the path ten times a second, and the
// moments things changed. Perk and weapon ids are the game's (web/src/perks.json, web/src/weapons.json).

import type { Timeline } from "./api-types";

export const PROBE_BYTES = 108;
// The probe's timers, in order.
export const EFFECTS = ["Double Experience", "Weapon Power Up", "Fire Bullets", "Freeze", "Reflex Boost", "Energizer", "Shield", "Speed"];
const TICKS_PER_SAMPLE = 60;
const TICKS_PER_POINT = 6;
// A timer that lapses for less than this between points continues the same span.
const SPAN_GAP_S = 0.25;

export class TimelineRecorder {
  private tick = 0;
  private weapon = -1;
  private level = -1;
  private nukes = 0;
  private last: DataView | null = null;
  private readonly timeline: Timeline;

  constructor(seed: number) {
    this.timeline = { seed, duration_s: 0, samples: [], path: [], weapons: [], perks: [], levels: [], nukes: [], effects: {} };
  }

  record(probe: DataView): void {
    const f32 = (at: number) => probe.getFloat32(at, true);
    const i32 = (at: number) => probe.getInt32(at, true);
    const t = i32(16) / 1000;
    const line = this.timeline;
    const weapon = i32(28);
    if (weapon !== this.weapon) line.weapons.push({ t, id: (this.weapon = weapon) });
    const level = i32(24);
    if (this.level !== -1 && level > this.level) line.levels.push({ t, level });
    this.level = level;
    for (let i = 0; i < i32(40); i++) line.perks.push({ t, id: i32(44 + i * 4) });
    for (; this.nukes < i32(36); this.nukes++) line.nukes.push(t);
    if (this.tick % TICKS_PER_POINT === 0) {
      line.path.push([t, Math.round(f32(0)), Math.round(f32(4))]);
      EFFECTS.forEach((name, i) => {
        if (f32(76 + i * 4) <= 0) return;
        const spans = (line.effects[name] ??= []);
        const span = spans.at(-1);
        if (span && span[1] >= t - SPAN_GAP_S) span[1] = t;
        else spans.push([t, t]);
      });
    }
    if (this.tick % TICKS_PER_SAMPLE === 0) this.sample(probe);
    this.last = probe;
    this.tick++;
  }

  finish(): Timeline {
    // The final tick is always a sample, so the curves end where the run did.
    if ((this.tick - 1) % TICKS_PER_SAMPLE !== 0 && this.last) this.sample(this.last);
    this.timeline.duration_s = this.timeline.samples.at(-1)?.[0] ?? 0;
    return this.timeline;
  }

  private sample(probe: DataView): void {
    const t = probe.getInt32(16, true) / 1000;
    const health = Math.max(0, probe.getFloat32(8, true));
    this.timeline.samples.push([
      t,
      probe.getInt32(20, true),
      probe.getInt32(24, true),
      Math.round(health * 10) / 10,
      probe.getInt32(32, true),
      Math.round(probe.getFloat32(12, true)),
    ]);
  }
}
