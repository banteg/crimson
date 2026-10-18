// The network between two co-op peers as the checks simulate the transport
// (client/web/coop.js): game_coop.mjs's engines and game_coop_live.mjs's booted
// games. A message takes 10 to 70 ms one way, or as a profile has it (`ms` ±
// `jitter`). Channel 0 is best effort: its messages can overtake each other,
// some are lost, and once a burst of them in a row, or every `every` ms one
// peer's next `burst`, the peers taking turns (`bursts`); channel 1 is reliable
// and ordered. A stutter holds one peer's frames and arrivals for a while. A
// subclass plays a peer's frame (`frame`), hands it what arrives (`receive`)
// and says how the peers stand when one waits too long (`describe`); its peers
// carry their seat, the time of their next frame (`at`) and whether they are
// gone (neither frames nor takes arrivals). Both gates read the engine's
// counters here (coopStats).

// A seeded generator of numbers in [0, 1).
export const prng = (s) => () => ((s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x9e3779b9) | 0) >>> 0) / 2 ** 32;

// The engine's counters (host/coop.inc CoopStats) in order, each a name or a name and how many in a row; then the
// session's (CoopWireStats).
const STATS = [
  "ticks",
  "resimulated",
  "rollbacks",
  "max_depth",
  "stalls",
  "guesses_one",
  "guesses_two",
  "mispredictions_one",
  "mispredictions_two",
  "picker_waits_one",
  "picker_waits_two",
  "guessed_lead",
  "opens_one",
  "opens_two",
  "double_opens",
  "dropped_opens",
  "survivor_menus",
  "extra_picks",
  "overflow_rollbacks",
  "overflow_free_rollbacks",
  "overflow_decal_holds",
  "queued_commits",
  "unseen_bakes",
  "slot_bytes",
  "max_lead",
  "checked",
  ["depths", 12],
  ["frame_ms", 6],
  "worst_frame_us",
  "stalled_network",
  "stalled_perk",
  "frame_resimulated",
  "late_ticks",
  "late_lead",
  "revised_deaths",
  "revised_wipes",
];
const WIRE = ["sent", "received", "lost", "stale", "repairs", "repaired", "rtt_ms"];
// Where the engine's counter `name` starts among game_coop_stats' words.
export function coopStatIndex(name) {
  let at = 0;
  for (const s of STATS) {
    if ((Array.isArray(s) ? s[0] : s) === name) return at;
    at += Array.isArray(s) ? s[1] : 1;
  }
  throw Error(`no counter ${name}`);
}
// A module's counters by name (`depths` and `frame_ms` arrays), its session's as `wire`.
export function coopStats(g) {
  const size = STATS.reduce((n, s) => n + (Array.isArray(s) ? s[1] : 1), WIRE.length);
  const words = new Int32Array(g.memory.buffer, g.game_coop_stats(), size);
  let at = 0;
  const stats = Object.fromEntries(
    STATS.map((s) => (Array.isArray(s) ? [s[0], Array.from(words.subarray(at, (at += s[1])))] : [s, words[at++]])),
  );
  stats.wire = Object.fromEntries(WIRE.map((name) => [name, words[at++]]));
  return stats;
}

export class Link {
  constructor(seed) {
    this.random = prng(seed);
    this.peers = [];
    this.now = 0;
    this.flights = [];
    this.order = 0;
    this.ordered = [0, 0];
    this.hitch = null; // {peer, from, to}
    this.burst = null; // {from: seat, at, left}
    this.loss = 0;
    this.profile = { ms: 40, jitter: 30 };
    this.bursts = null; // {every, burst, from: seat, at}
  }
  // What `p` sends goes to its partner.
  send(p, channel, bytes) {
    const { ms, jitter } = this.profile;
    let at = this.now + (ms - jitter) + 2 * jitter * this.random();
    if (channel === 0) {
      const bursts = this.bursts;
      if (bursts && this.now >= bursts.at && !this.burst?.left) {
        this.burst = { from: bursts.from, at: this.now, left: bursts.burst };
        bursts.from = 1 - bursts.from;
        bursts.at = this.now + bursts.every;
      }
      const burst = this.burst;
      if (burst?.from === p.seat && this.now >= burst.at && burst.left > 0) return void burst.left--;
      if (this.random() < this.loss) return;
    } else {
      at = this.ordered[p.seat] = Math.max(at, this.ordered[p.seat]);
    }
    this.flights.push({ at, order: this.order++, to: this.peers[1 - p.seat], channel, bytes });
  }
  // Frames and arrivals in time order until `done`; a stutter holds its peer's frames and arrivals.
  until(done, what, limit = 600000) {
    const deadline = this.now + limit;
    while (!done()) {
      const hitch = this.hitch;
      let next = null;
      for (const f of this.flights) if (!next || f.at < next.at || (f.at === next.at && f.order < next.order)) next = f;
      const p = this.peers.filter((q) => !q.gone).reduce((a, b) => (b.at < a.at ? b : a));
      const arrival = next && next.at < p.at ? next : null;
      const at = arrival ? arrival.at : p.at;
      if (at > deadline) throw Error(`${what}: not by ${Math.round(this.now)} ms ${JSON.stringify(this.describe())}`);
      this.now = at;
      if (hitch?.peer === (arrival ? arrival.to : p) && at >= hitch.from && at < hitch.to) {
        if (arrival) arrival.at = hitch.to;
        else p.at = hitch.to;
        continue;
      }
      if (arrival) {
        this.flights.splice(this.flights.indexOf(arrival), 1);
        this.receive(arrival.to, arrival.channel, arrival.bytes);
      } else {
        this.frame(p);
      }
    }
  }
}
