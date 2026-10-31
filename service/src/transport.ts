// The crimson-core input stream for a replay, a port of crimson-core/checks/replay.py: a 69-word config, then per
// tick each player's four f32 axes and flag word (player one first), the command count and each command as (kind,
// argument). A perk command carries no player: the core knows whose perk menu is open.

import { ClBuild, type CustomQuest, GameMode, type Replay } from "./replay";

export const CONFIG_BYTES = 69 * 4;
const SEED_WORD = 0;
// The config word holding the player count, which the stream gained after runs were first accepted.
const PLAYERS_WORD = 12;
// The first of the words the config gained after its runs' ids were frozen: rules, the legacy co-op reload and the
// build whose rules the run plays.
const RULES_WORD = 66;
const BUILD_WORD = 68;
export const QUEST_HEAD_BYTES = 10 * 4;
export const QUEST_SPAWN_BYTES = 24;
export const QUEST_BYTES = QUEST_HEAD_BYTES + 256 * QUEST_SPAWN_BYTES;
export const INPUT_BYTES = 20;
const COMMAND_BYTES = 8;
export const MAX_TICK_COMMANDS = 16;

export class TransportError extends Error {}

// A tick's inputs and command count, before its commands.
export const tickBytes = (players: number) => players * INPUT_BYTES + 4;

export function encodePortableQuest(quest: CustomQuest): Uint8Array {
  const bytes = new Uint8Array(QUEST_BYTES);
  const view = new DataView(bytes.buffer);
  let bonuses = 0;
  for (const id of quest.no_bonuses) bonuses |= 1 << id;
  let perksLo = 0, perksHi = 0;
  for (const id of quest.no_perks) {
    if (id < 32) perksLo |= 1 << id;
    else perksHi |= 1 << (id - 32);
  }
  let weaponsLo = 0, weaponsHi = 0;
  for (const id of quest.no_weapons) {
    if (id < 32) weaponsLo |= 1 << id;
    else weaponsHi |= 1 << (id - 32);
  }
  const head = [
    quest.start_weapon_id,
    quest.terrain_slots[0],
    quest.terrain_slots[1],
    quest.terrain_slots[2],
    quest.entries.length,
    bonuses >>> 0,
    perksLo >>> 0,
    perksHi >>> 0,
    weaponsLo >>> 0,
    weaponsHi >>> 0,
  ];
  head.forEach((word, i) => view.setUint32(i * 4, word >>> 0, true));
  quest.entries.forEach((e, i) => {
    const at = QUEST_HEAD_BYTES + i * QUEST_SPAWN_BYTES;
    view.setFloat32(at, e.pos.x, true);
    view.setFloat32(at + 4, e.pos.y, true);
    view.setFloat32(at + 8, e.heading, true);
    view.setInt32(at + 12, e.spawn_id, true);
    view.setInt32(at + 16, e.trigger_ms, true);
    view.setInt32(at + 20, e.count, true);
  });
  return bytes;
}

export function encodeTransport(replay: Replay): Uint8Array {
  const run = replay.run;
  const players = run.player_count;
  if ((players !== 1 && players !== 2) || ![GameMode.SURVIVAL, GameMode.RUSH, GameMode.QUESTS].includes(run.game_mode_id as 1 | 2 | 3))
    throw new TransportError("The core supports one or two players in Rush, Survival or Quests");
  const custom = run.custom_quest;
  const headBytes = CONFIG_BYTES + (custom ? QUEST_BYTES : 0);
  const ticks = replay.ticks;
  const commandCount = [...ticks.commands.values()].reduce((sum, commands) => sum + commands.length, 0);
  const bytes = new Uint8Array(headBytes + ticks.length * tickBytes(players) + commandCount * COMMAND_BYTES);
  const view = new DataView(bytes.buffer);
  const config = [
    run.seed,
    run.game_mode_id,
    custom ? 0 : (run.quest_level?.major ?? 1),
    custom ? 0 : (run.quest_level?.minor ?? 1),
    run.status.quest_unlock_index,
    run.status.quest_unlock_index_hardcore,
    run.detail_preset,
    run.violence_disabled,
    Number(run.friendly_fire),
    Number(run.hardcore),
    run.quest_fail_retry_count,
    Number(run.preserve_bugs),
    run.player_count,
    ...run.status.weapon_usage_counts,
    replay.rules,
    // Ranked co-op (#768) shipped after the manual-reload fix (#758).
    // The service never verifies the older local-only co-op profile.
    0,
    run.cl_build,
  ];
  config.forEach((word, i) => view.setUint32(i * 4, word >>> 0, true));
  if (custom) bytes.set(encodePortableQuest(custom), CONFIG_BYTES);
  let at = headBytes;
  for (let tick = 0; tick < ticks.length; tick++) {
    const commands = ticks.commands.get(tick) ?? [];
    if (commands.length > MAX_TICK_COMMANDS) throw new TransportError("Unsupported player or command count");
    for (let player = 0; player < players; player++, at += INPUT_BYTES) {
      const [mx, my, ax, ay, flags] = ticks.input(tick, player);
      [mx, my, ax, ay].forEach((axis, i) => view.setFloat32(at + i * 4, axis, true));
      view.setUint32(at + 16, flags, true);
    }
    view.setUint32(at, commands.length, true);
    at += 4;
    for (const command of commands) {
      if (command.player_index >= players) throw new TransportError("Unsupported command player");
      if (command.type === "perk_pick") view.setInt32(at, 1, true), view.setInt32(at + 4, command.choice_index, true);
      else if (command.type === "perk_menu_open") view.setInt32(at, 2, true), view.setInt32(at + 4, 0, true);
      else throw new TransportError(`Unsupported command: ${command.type}`);
      at += COMMAND_BYTES;
    }
  }
  return bytes;
}

// The bytes a run's id hashes. Ids name stored replays, links and the duplicate check, so they stay put when the
// stream's layout changes: a one-player run hashes its stream as the service first encoded it, without the player
// count, which the stream gained later; a co-op run hashes its whole stream, the count included. (A ranked run's
// weapon usage words are zero, so the shifted one-player bytes never spell a co-op stream.) A rules-2 run tags those
// bytes with its rules, and a run of another build than 1.9.93 tags that with its build, so the same inputs under
// 1.9.8's rules are another run; 1.9.93's ids, which predate builds, stay as they were.
export function runIdentity(transport: Uint8Array): Uint8Array {
  const view = new DataView(transport.buffer, transport.byteOffset, transport.byteLength);
  const rules = view.getUint32(RULES_WORD * 4, true);
  const build = view.getUint32(BUILD_WORD * 4, true);
  // Freeze the old identity independently of the appended config words.
  const legacy = new Uint8Array(transport.length - (CONFIG_BYTES - RULES_WORD * 4));
  legacy.set(transport.subarray(0, RULES_WORD * 4));
  legacy.set(transport.subarray(CONFIG_BYTES), RULES_WORD * 4);
  if (rules !== 1 && rules !== 2) throw new TransportError(`Unsupported rules ${rules}`);
  const identity = rules === 1 ? legacyIdentity(legacy) : tagged("crimson:run:rules\0", rules, legacy);
  return build === ClBuild.V1_9_93 ? identity : tagged("crimson:run:build\0", build, identity);
}

// `transport`'s ticks as they stream from `seed` under `rules` and `clBuild`'s rules: only those three words differ.
export function asClaimed(transport: Uint8Array, seed: number, rules: number, clBuild: number): Uint8Array {
  const bytes = transport.slice();
  const view = new DataView(bytes.buffer);
  view.setUint32(SEED_WORD * 4, seed, true);
  view.setUint32(RULES_WORD * 4, rules, true);
  view.setUint32(BUILD_WORD * 4, clBuild, true);
  return bytes;
}

// `bytes` after a tag, its NUL included, and a little-endian word.
function tagged(tag: string, word: number, bytes: Uint8Array): Uint8Array {
  const head = new TextEncoder().encode(tag);
  const out = new Uint8Array(head.length + 4 + bytes.length);
  out.set(head);
  new DataView(out.buffer).setUint32(head.length, word, true);
  out.set(bytes, head.length + 4);
  return out;
}

function legacyIdentity(transport: Uint8Array): Uint8Array {
  const at = PLAYERS_WORD * 4;
  if (new DataView(transport.buffer, transport.byteOffset + at, 4).getUint32(0, true) !== 1) return transport;
  const bytes = new Uint8Array(transport.length - 4);
  bytes.set(transport.subarray(0, at));
  bytes.set(transport.subarray(at + 4), at);
  return bytes;
}
