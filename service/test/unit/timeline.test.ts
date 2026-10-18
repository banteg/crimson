import { describe, expect, it } from "vitest";
import { PROBE_BYTES, TimelineRecorder } from "../../src/timeline";

// A probe as crimson-core/host/api.h lays it out, with each player's place, health, weapon and Shield timer.
function probe(tick: number, players: { x: number; health: number; weapon: number; shield: number }[]): DataView {
  const view = new DataView(new ArrayBuffer(PROBE_BYTES));
  view.setInt32(4, tick * 16, true);
  view.setInt32(12, 1, true);
  players.forEach((player, i) => {
    const at = 80 + i * 28;
    view.setFloat32(at, player.x, true);
    view.setFloat32(at + 4, 500, true);
    view.setFloat32(at + 8, player.health, true);
    view.setInt32(at + 12, player.weapon, true);
    view.setFloat32(at + 20, player.shield, true);
  });
  return view;
}

describe("co-op timelines", () => {
  it("a player healed back up after going down keeps being recorded, and only their last fall is their death", () => {
    const recorder = new TimelineRecorder(1, 2);
    const one = { x: 100, health: 100, weapon: 1, shield: 0 };
    for (let tick = 0; tick <= 300; tick++) {
      // Player two goes down at tick 60, a MediKit gets them up at 120, they take the Shotgun and a Shield at 150, and
      // go down for good at 240 with the Shield still running.
      const down = (tick >= 60 && tick < 120) || tick >= 240;
      const two = { x: 200 + tick, health: down ? -5 : 50, weapon: tick >= 150 ? 3 : 1, shield: tick >= 150 ? 5 : 0 };
      recorder.record(probe(tick, [one, two]));
    }
    const timeline = recorder.finish();
    const [first, second] = timeline.players!;

    expect(first!.death_s).toBeNull();
    expect(first!.path.at(-1)![0]).toBe(4.8);
    expect(second!.death_s).toBe(3.84);
    // The path goes on after the revive and ends where they fell for good.
    expect(second!.path.at(-1)).toEqual([3.84, 440, 500]);
    expect(second!.path.some(([t]) => t > 1.92 && t < 3.84)).toBe(true);
    expect(second!.weapons).toEqual([{ t: 0, id: 1 }, { t: 2.4, id: 3 }]);
    // Their Shield counts while they stand.
    expect(second!.effects).toEqual({ Shield: [[2.4, 3.744]] });
    expect(second!.health).toEqual([50, 0, 50, 50, 0, 0]);
  });
});
