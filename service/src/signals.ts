// A run's input signals (docs/rewrite/bots.md): measured while the verifier replays the run, shown to moderators, and
// never deciding anything on their own. Each flags a bot that does not hide; noise or smoothing beats any of them.

import { tickControls } from "./replay";

export interface Signals {
  // The ticks measured: those where player one is alive.
  ticks: number;
  // Share of aimed ticks whose aim point lies on a living creature's centre.
  aim_on_creature: number;
  // Share of pad moves off the eight key directions that are exactly unit length.
  exact_moves: number;
  // Move direction turns over 90° from one tick to the next, per minute.
  reversals_per_min: number;
  // The 99th percentile of the aim point's movement per tick, in world units.
  aim_jump_p99: number;
  // Fire presses held for exactly one tick.
  one_tick_fire: number;
}

// Above these a signal is flagged. Astra's runs measured at least 0.15, 1.0, 257, 213 and 327; the human Survival runs
// at most 0.0015, 0, 1.7, 35 and 0.
export const SIGNAL_FLAGS = {
  aim_on_creature: 0.02,
  exact_moves: 0.5,
  reversals_per_min: 30,
  aim_jump_p99: 120,
  one_tick_fire: 50,
} as const;
export type SignalName = keyof typeof SIGNAL_FLAGS;

export function flagged(signals: Signals): SignalName[] {
  return (Object.keys(SIGNAL_FLAGS) as SignalName[]).filter((name) => signals[name] > SIGNAL_FLAGS[name]);
}

const MOVE_STATIC = 2;
const MOVE_PAD = 3;
const AIM_MOUSE = 0;
const AIM_MOUSE_RELATIVE = 3;
const AIM_PAD = 4;
const FIRE_DOWN = 1;
const KEY_FORWARD = 1 << 4;
const KEY_BACKWARD = 1 << 5;
const KEY_LEFT = 1 << 6;
const KEY_RIGHT = 1 << 7;
const ON_CREATURE = 0.5;
// A stick below this is resting; its direction means nothing.
const MOVING = 0.2;
const UNIT = 1e-6;
const TICKS_PER_MINUTE = 3600;

interface Point {
  x: number;
  y: number;
}

export class SignalMeter {
  private ticks = 0;
  private aimed = 0;
  private onCreature = 0;
  private padMoves = 0;
  private exactMoves = 0;
  private reversals = 0;
  private oneTickFire = 0;
  private fireHeld = 0;
  private jumps: number[] = [];
  private lastAim: Point | null = null;
  private lastHeading: number | null = null;

  // One tick's input before the tick runs: where player one stands, the ranked view's camera, and the distance from
  // a world point to the nearest living creature.
  record(
    [moveX, moveY, aimX, aimY, flags]: [number, number, number, number, number],
    player: Point & { alive: boolean },
    camera: Point,
    nearest: (x: number, y: number) => number,
  ): void {
    if (!player.alive) {
      this.lastAim = this.lastHeading = null;
      this.releaseFire();
      return;
    }
    this.ticks++;
    const { moveMode, aimScheme } = tickControls(flags);

    // The world point the aim reaches; keyboard and joystick aim only turn.
    const aim =
      aimScheme === AIM_MOUSE ? { x: aimX, y: aimY }
      : aimScheme === AIM_PAD ? { x: player.x + aimX, y: player.y + aimY }
      : aimScheme === AIM_MOUSE_RELATIVE ? { x: aimX - camera.x, y: aimY - camera.y }
      : null;
    if (aim) {
      const distance = nearest(aim.x, aim.y);
      if (Number.isFinite(distance)) {
        this.aimed++;
        if (distance <= ON_CREATURE) this.onCreature++;
      }
      if (this.lastAim) this.jumps.push(Math.hypot(aim.x - this.lastAim.x, aim.y - this.lastAim.y));
    }
    this.lastAim = aim;

    const move = moveMode === MOVE_PAD ? { x: moveX, y: moveY } : moveMode === MOVE_STATIC ? keyMove(flags) : null;
    // Keys bound to the pad move along the eight key directions at full length; a stick hardly ever does.
    const offKeys = Math.abs(moveX) > UNIT && Math.abs(moveY) > UNIT && Math.abs(Math.abs(moveX) - Math.abs(moveY)) > UNIT;
    if (moveMode === MOVE_PAD && offKeys) {
      this.padMoves++;
      if (Math.abs(Math.hypot(moveX, moveY) - 1) < UNIT) this.exactMoves++;
    }
    if (move && Math.hypot(move.x, move.y) > MOVING) {
      const heading = Math.atan2(move.y, move.x);
      if (this.lastHeading !== null && Math.abs(Math.atan2(Math.sin(heading - this.lastHeading), Math.cos(heading - this.lastHeading))) > Math.PI / 2)
        this.reversals++;
      this.lastHeading = heading;
    } else {
      this.lastHeading = null;
    }

    if (flags & FIRE_DOWN) this.fireHeld++;
    else this.releaseFire();
  }

  finish(): Signals {
    this.releaseFire();
    const jumps = this.jumps.sort((a, b) => a - b);
    const share = (part: number, whole: number) => (whole ? round(part / whole, 4) : 0);
    return {
      ticks: this.ticks,
      aim_on_creature: share(this.onCreature, this.aimed),
      exact_moves: share(this.exactMoves, this.padMoves),
      reversals_per_min: this.ticks ? round((this.reversals * TICKS_PER_MINUTE) / this.ticks, 1) : 0,
      aim_jump_p99: jumps.length ? round(jumps[Math.min(jumps.length - 1, Math.floor(jumps.length * 0.99))]!, 1) : 0,
      one_tick_fire: this.oneTickFire,
    };
  }

  private releaseFire(): void {
    if (this.fireHeld === 1) this.oneTickFire++;
    this.fireHeld = 0;
  }
}

// The direction static movement's held keys steer.
function keyMove(flags: number): Point {
  return {
    x: (flags & KEY_RIGHT ? 1 : 0) - (flags & KEY_LEFT ? 1 : 0),
    y: (flags & KEY_BACKWARD ? 1 : 0) - (flags & KEY_FORWARD ? 1 : 0),
  };
}

const round = (value: number, digits: number) => Math.round(value * 10 ** digits) / 10 ** digits;
