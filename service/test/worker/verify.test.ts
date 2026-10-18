import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { decodeReplay, inflateReplay } from "../../src/replay";
import { hex, sha256 } from "../../src/crypto";
import { encodeTransport } from "../../src/transport";
import { TickMonitor, verifyRun } from "../../src/verify";
import vectors from "../vectors.json";

const decode64 = (text: string) => Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
const timelineOf = async (file: string) => {
  const replay = decodeReplay(inflateReplay(decode64(file)));
  const verdict = await verifyRun(env, replay, encodeTransport(replay));
  if (!verdict.ok) throw new Error(verdict.reason);
  return verdict.timeline;
};

describe("timelines", () => {
  it("a one-player run's timeline stays the one its page has always read", async () => {
    const timeline = await timelineOf(vectors.ranked_run);
    expect(timeline).not.toHaveProperty("players");
    // JSON.stringify of the timeline the probe of player one alone recorded (before co-op timelines), as R2 stores it.
    expect(hex(await sha256(new TextEncoder().encode(JSON.stringify(timeline))))).toBe("742ef30f92441a643262ca0dbc488eeb781dec5d9134ea827c148f3f32ef1b97");
  });

  it("a co-op run's timeline has each player's path, health, weapons and death, and player one's at the top", async () => {
    const timeline = await timelineOf(vectors.coop_run.file);
    const [one, two] = timeline.players!;
    // Both hold the pistol where they spawned, firing in circles; player two dies first, then player one ends the run.
    expect(timeline.players).toHaveLength(2);
    expect([one!.death_s, two!.death_s]).toEqual([31.568, 27.904]);
    expect(one!.weapons).toEqual([{ t: 0.016, id: 1 }]);
    expect(two!.weapons).toEqual([{ t: 0.016, id: 1 }]);
    expect([one!.path[0], two!.path[0]]).toEqual([[0.016, 512, 512], [0.016, 432, 432]]);
    // A path ends where its player died.
    expect([one!.path.at(-1)![0], two!.path.at(-1)![0]]).toEqual([31.568, 27.904]);
    for (const player of [one!, two!]) {
      expect(player.health).toHaveLength(timeline.samples.length);
      expect(player.health.at(-1)).toBe(0);
      expect(player.health[0]).toBe(100);
    }
    // The top level stays player one's, as a one-player page reads it.
    expect(timeline.samples.map((sample) => sample[3])).toEqual(one!.health);
    expect(timeline.path.slice(0, one!.path.length - 1)).toEqual(one!.path.slice(0, -1));
    expect(timeline.weapons).toEqual(one!.weapons);
    expect(timeline.duration_s).toBe(32.8);
  });

  it("a co-op quest both players clear has no deaths", async () => {
    const timeline = await timelineOf(vectors.coop_run.quest_file);
    expect(timeline.players!.map((player) => [player.death_s, player.weapons])).toEqual([
      [null, [{ t: 0.016, id: 3 }]],
      [null, [{ t: 0.016, id: 3 }]],
    ]);
  });
});

describe("two players", () => {
  it.each([
    ["Survival run", vectors.coop_run.file],
    ["custom quest clear", vectors.coop_run.quest_file],
  ])("a co-op %s replays to the result Python recorded, player two's and the quest time too", async (_, file) => {
    const replay = decodeReplay(inflateReplay(decode64(file)));
    const verdict = await verifyRun(env, replay, encodeTransport(replay));

    expect(verdict).toMatchObject({ ok: true });
    expect(replay.result.players).toHaveLength(2);
    expect(verdict.signals.ticks).toBeGreaterThan(replay.ticks.length);
  });

  // Static movement with mouse aim, and point-click movement with mouse aim.
  const STATIC = (1 << 8) | (2 << 9) | (1 << 12);
  const POINT_CLICK = (1 << 8) | (4 << 9) | (1 << 12);
  const aimAt = (y: number, flags = STATIC): [number, number, number, number, number] => [0, 0, 600, y, flags];
  const target = (y: number): [number, number, number, number, number] => [600, y, 600, 500, POINT_CLICK];

  // Player one near the arena's top, player two near its bottom: their midpoint's view shows world y 384..1152 less
  // the clamp, 256..1024; player one's own shows 0..768.
  function pair() {
    const players = [
      { x: 512, y: 200, health: 100 },
      { x: 512, y: 900, health: 100 },
    ];
    const core = {
      portable_player_x: (i: number) => players[i]!.x,
      portable_player_y: (i: number) => players[i]!.y,
      portable_player_health: (i: number) => players[i]!.health,
    };
    const monitor = new TickMonitor(2);
    monitor.updateCamera(core);
    return { players, monitor, update: () => monitor.updateCamera(core) };
  }

  it("every player's aim stays inside the view the camera, between the living players, shows", () => {
    const { players, monitor, update } = pair();
    expect([monitor.check(0, aimAt(950)), monitor.check(1, aimAt(950))]).toEqual([null, null]);

    // Player two dies: the camera follows player one alone.
    players[1]!.health = 0;
    update();
    expect(monitor.check(1, aimAt(950))).toBe("aim outside the 1024x768 view");
    // With nobody alive it stays where it was.
    players[0]!.health = -1;
    players[0]!.y = 1000;
    update();
    expect(monitor.check(0, aimAt(950))).toBe("aim outside the 1024x768 view");
  });

  it("each player's point-click target is checked when that player sets it", () => {
    const { players, monitor, update } = pair();
    expect(monitor.check(0, target(950))).toBeNull();
    players[1]!.health = 0;
    update();
    // Player one walks on to a target set in view; player two sets the same one now, out of view.
    expect(monitor.check(0, target(950))).toBeNull();
    expect(monitor.check(1, target(950))).toBe("move target outside the 1024x768 view");
  });
});
