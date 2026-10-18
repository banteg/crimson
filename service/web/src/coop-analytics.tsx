import { For, type JSX, Show } from "solid-js";
import type { PlayAnalyticsView } from "../../src/api-types";
import PLAY_ANALYTICS from "../../../crimson-core/client/web/analytics.json";
import { BLUE, GOLD, GREEN, grouped, RED } from "./run";

// The co-op charts are narrow, so that at phone width their text scales down little and a wide panel holds two side
// by side (.coop-charts).
const W = 360;
const LABEL = 76;
const ROW = 22;

const sum = (values: number[]) => values.reduce((a, b) => a + b, 0);
const percent = (part: number, whole: number) => (whole ? `${((100 * part) / whole).toFixed(part && part < whole / 1000 ? 2 : 1)}%` : "–");
// Bucket labels from analytics.json's bounds: under the first, each up to the next, and the last and longer.
const ranges = (bounds: number[]) => [`<${bounds[0]}`, ...bounds.slice(1).map((to, i) => `${bounds[i]}–${to}`), `${bounds.at(-1)}+`];
// `n` colours from green through gold to red: the buckets from fast to slow.
function ramp(n: number): string[] {
  const rgb = (color: string) => color.match(/\d+/g)!.map(Number);
  const stops = [GREEN, GOLD, RED].map(rgb);
  return Array.from({ length: n }, (_, i) => {
    const at = (i / Math.max(1, n - 1)) * (stops.length - 1), from = Math.min(Math.floor(at), stops.length - 2), f = at - from;
    return `rgb(${stops[from]!.map((c, k) => Math.round(c + (stops[from + 1]![k]! - c) * f)).join(",")})`;
  });
}

function Chart(props: { title: JSX.Element; height: number; children: JSX.Element }) {
  return (
    <figure class="coop-chart">
      <figcaption>{props.title}</figcaption>
      <svg viewBox={`0 0 ${W} ${props.height}`} class="chart">{props.children}</svg>
    </figure>
  );
}

// A bar a transport, its exact value at its end; a row without a value (null) has neither.
function Bars(props: { title: string; rows: { label: string; value: number | null; text: string }[]; color: string }) {
  const most = () => Math.max(...props.rows.map((row) => row.value ?? 0)) || 1;
  const span = W - LABEL - 70;
  const width = (value: number) => Math.max(value ? 1 : 0, (value / most()) * span);
  return (
    <Chart title={props.title} height={props.rows.length * ROW}>
      <For each={props.rows}>
        {(row, i) => (
          <>
            <text x={LABEL - 8} y={i() * ROW + 15} class="label" text-anchor="end">{row.label}</text>
            <rect x={LABEL} y={i() * ROW + 4} width={width(row.value ?? 0)} height={ROW - 8} fill={props.color} fill-opacity="0.7">
              <title>{`${row.label}: ${row.text}`}</title>
            </rect>
            <text x={LABEL + width(row.value ?? 0) + 6} y={i() * ROW + 15} class="value">{row.text}</text>
          </>
        )}
      </For>
    </Chart>
  );
}

// A bar a transport split into its buckets' shares, each with its count where it fits, and the buckets' legend.
function Shares(props: { title: string; rows: { label: string; counts: number[] }[]; names: string[]; unit: string }) {
  const colors = ramp(props.names.length);
  const span = W - LABEL - 4;
  // The legend's swatches from the bars' left edge, wrapping as the bars' width runs out (11px Courier, about 6.6px
  // a character).
  const top = props.rows.length * ROW + 8;
  const legend: { x: number; y: number }[] = [];
  for (let x = LABEL, y = top, i = 0; i < props.names.length; i++) {
    const width = 14 + props.names[i]!.length * 6.6;
    if (x + width > W && x > LABEL) [x, y] = [LABEL, y + 16];
    legend.push({ x, y });
    x += width + 12;
  }
  const segments = (counts: number[]) => {
    const total = sum(counts);
    let x = LABEL;
    return counts.map((n, bucket) => {
      const width = total ? (n / total) * span : 0;
      x += width;
      return { n, bucket, x: x - width, width, share: percent(n, total) };
    });
  };
  return (
    <Chart title={props.title} height={legend.at(-1)!.y + 14}>
      <For each={props.rows}>
        {(row, i) => (
          <>
            <text x={LABEL - 8} y={i() * ROW + 15} class="label" text-anchor="end">{row.label}</text>
            <For each={segments(row.counts).filter((segment) => segment.n)}>
              {(segment) => (
                <>
                  <rect x={segment.x} y={i() * ROW + 3} width={Math.max(1, segment.width - 1)} height={ROW - 6} fill={colors[segment.bucket]} fill-opacity="0.75">
                    <title>{`${row.label}, ${props.names[segment.bucket]} ${props.unit}: ${grouped(segment.n)} (${segment.share})`}</title>
                  </rect>
                  <Show when={segment.width >= 8 * String(segment.n).length + 4}>
                    <text x={segment.x + segment.width / 2} y={i() * ROW + 15} class="ink" text-anchor="middle">{segment.n}</text>
                  </Show>
                </>
              )}
            </For>
          </>
        )}
      </For>
      <For each={props.names}>
        {(name, bucket) => (
          <>
            <rect x={legend[bucket()]!.x} y={legend[bucket()]!.y} width={10} height={10} fill={colors[bucket()]} fill-opacity="0.75" />
            <text x={legend[bucket()]!.x + 14} y={legend[bucket()]!.y + 9} class="axis small">{name}</text>
          </>
        )}
      </For>
    </Chart>
  );
}

// Counts by bucket as bars, each with its share above it.
function Histogram(props: { title: JSX.Element; counts: number[]; labels: string[]; colors: string[]; unit: string }) {
  const top = 16, bottom = 96, slot = W / props.counts.length;
  const total = () => sum(props.counts);
  const most = () => Math.max(...props.counts) || 1;
  const y = (n: number) => bottom - (n / most()) * (bottom - top);
  // Whole percents; a share under one shows as such, its exact count in the bar's title.
  const share = (n: number) => (!n ? "" : (100 * n) / total() < 1 ? "<1%" : `${Math.round((100 * n) / total())}%`);
  return (
    <Chart title={props.title} height={bottom + 18}>
      <line x1={0} x2={W} y1={bottom + 0.5} y2={bottom + 0.5} class="grid" />
      <For each={props.counts}>
        {(n, i) => (
          <>
            <rect x={i() * slot + 2} y={y(n)} width={slot - 4} height={bottom - y(n)} fill={props.colors[i()]} fill-opacity="0.7">
              <title>{`${props.labels[i()]} ${props.unit}: ${grouped(n)} (${percent(n, total())})`}</title>
            </rect>
            <text x={(i() + 0.5) * slot} y={y(n) - 4} class="value small" text-anchor="middle">{share(n)}</text>
            <text x={(i() + 0.5) * slot} y={bottom + 14} class="axis small" text-anchor="middle">{props.labels[i()]}</text>
          </>
        )}
      </For>
    </Chart>
  );
}

// Co-op sessions over the last 30 days by transport, as each page reports its own session when it ends.
export function CoopAnalytics(props: { rows: PlayAnalyticsView["coop"] }) {
  const { transports, rtt_ms: rttMs, depths, frame_ms: frameMs } = PLAY_ANALYTICS.coop;
  const count = (transport: string, metric: string, bucket = 0) =>
    props.rows.find((row) => row.transport === transport && row.metric === metric && row.bucket === bucket)?.count ?? 0;
  const series = (transport: string, metric: string, length: number) => Array.from({ length }, (_, i) => count(transport, metric, i));
  const used = transports.filter((transport) => count(transport, "sessions"));
  // Stalled frames a minute of the sessions that told them apart (split_seconds): pages from before the split sent
  // them together (`stalled`), which neither rate takes.
  const rate = (n: number, seconds: number) => (seconds ? n / (seconds / 60) : null);
  const stalls = (transport: string, metric: string) => {
    const value = rate(count(transport, metric), count(transport, "split_seconds"));
    return { label: transport, value, text: value === null ? "–" : value.toFixed(1) };
  };
  return (
    <>
      <h3>Co-op sessions</h3>
      <Show when={used.length} fallback={<p>No co-op sessions yet.</p>}>
        <div class="coop-charts">
          <Bars title="Sessions" color={BLUE} rows={used.map((t) => ({ label: t, value: count(t, "sessions"), text: grouped(count(t, "sessions")) }))} />
          <Bars title="Minutes in runs" color={BLUE}
            rows={used.map((t) => ({ label: t, value: count(t, "seconds") / 60, text: (count(t, "seconds") / 60).toFixed(1) }))} />
          <Bars title="Network stalls a minute" color={RED} rows={used.map((t) => stalls(t, "stalled_network"))} />
          <Bars title="Perk waits a minute" color={GOLD} rows={used.map((t) => stalls(t, "stalled_perk"))} />
          <Shares title="Round trips (ms), by session" names={ranges(rttMs)} unit="ms"
            rows={used.map((t) => ({ label: t, counts: series(t, "rtt", rttMs.length + 1) }))} />
          <figure class="coop-chart">
            <figcaption>Desyncs</figcaption>
            <table><tbody><For each={used}>{(t) => <tr>
              <td>{t}</td><td class="n">{count(t, "desyncs")}</td><td class="n muted">{percent(count(t, "desyncs"), count(t, "sessions"))}</td>
            </tr>}</For></tbody></table>
          </figure>
        </div>
        <h3>Rollbacks by depth (ticks)</h3>
        <div class="coop-charts">
          <For each={used}>{(t) => {
            const rollbacks = series(t, "depth", depths), minute = rate(sum(rollbacks), count(t, "seconds"));
            return <Histogram counts={rollbacks} labels={rollbacks.map((_, i) => String(i + 1))} colors={rollbacks.map(() => BLUE)}
              unit="ticks deep" title={<>{t}: <b>{minute === null ? "–" : minute.toFixed(1)}</b> a minute, {grouped(sum(rollbacks))} in all</>} />;
          }}</For>
        </div>
        <h3>Frames that ran ticks, by the time that took (ms)</h3>
        <div class="coop-charts">
          <For each={used}>{(t) => {
            const frames = series(t, "frame", frameMs.length + 1);
            return <Histogram counts={frames} labels={ranges(frameMs)} colors={ramp(frames.length)} unit="ms"
              title={<>{t}: {grouped(sum(frames))} frames</>} />;
          }}</For>
        </div>
      </Show>
      <p class="muted">Each page reports its own session as it ends, so a session between two players counts twice. Transport is the one a session last ran over, from both ends of its WebRTC pair: direct when neither relays, turn-udp or turn-tcp when the page's own TURN relay carries it, turn when only the partner's relay does (or a relay names no protocol), ws-relay through the room, unknown before the pair was read. Round trips count sessions. Network stalls are frames whose due ticks all waited for the partner's records or the prediction window; perk waits are frames that waited on a perk pick: the player's own request on its way to the partner, or the partner choosing on its perk screen. Neither counts a pause, and both are per minute of the sessions that reported them apart: pages from before the split reported them together, and count in neither.</p>
    </>
  );
}
