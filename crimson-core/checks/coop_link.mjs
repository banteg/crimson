// The network between two co-op peers as the checks simulate the transport
// (client/web/coop.js): game_coop.mjs's engines and game_coop_live.mjs's booted
// games. A message takes 10 to 70 ms one way. Channel 0 is best effort: its
// messages can overtake each other, some are lost, and once a burst of them in
// a row; channel 1 is reliable and ordered. A stutter holds one peer's frames
// and arrivals for a while. A subclass plays a peer's frame (`frame`), hands it
// what arrives (`receive`) and says how the peers stand when one waits too long
// (`describe`); its peers carry their seat, the time of their next frame (`at`)
// and whether they are gone (neither frames nor takes arrivals).

// A seeded generator of numbers in [0, 1).
export const prng = (s) => () => ((s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x9e3779b9) | 0) >>> 0) / 2 ** 32;

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
  }
  // What `p` sends goes to its partner.
  send(p, channel, bytes) {
    let at = this.now + 10 + 60 * this.random();
    if (channel === 0) {
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
