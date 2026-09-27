// Classic vs remake Survival progression charts (mechanics/modes/remake-survival.md).

const SERIES = ["Classic", "Remake", "Blitz"];

function seriesColors(dark) {
  return dark ? ["#3987e5", "#d95926", "#199e70"] : ["#2a78d6", "#eb6834", "#1baf7a"];
}

function isDark() {
  return document.body.dataset.mdColorScheme === "slate";
}

// ---- model ----

const classicLevelXp = (level) => (level <= 1 ? 0 : 1000 + Math.floor(1000 * Math.pow(level - 1, 1.8)));

const REMAKE_LEVEL_TABLE = [5000, 20000, 40000, 70000, 110000, 160000, 220000, 290000];

function remakeLevelXp(level) {
  if (level < 2) return 0;
  if (level <= 9) return REMAKE_LEVEL_TABLE[level - 2];
  if (level <= 15) return Math.round(0.2 * Math.pow(level, 2.5)) * 6000;
  return Math.round(Math.pow(level - 5, 4) / 30) * 2500;
}

const CLASSIC_WAVES = [
  [5, "Two 8-alien rings from left and right"],
  [9, "Red boss"],
  [11, "12-spider pack"],
  [13, "4 Deadly Fast aliens"],
  [15, "8 spiders, 4 per side"],
  [17, "Spider Boss"],
  [19, "Splitter spider pack"],
  [21, "Two splitter packs"],
  [26, "8 Plasma Shooter spiders"],
  [32, "Spider bosses and ranged columns"],
];

const REMAKE_STAGE_XP = [
  null, 11770, 16167, 22542, 31786, 45190, 64625, 92807, 133671, 192923, 278838, 403415,
  700000, 1400000, 2100000, 2800000, 3500000, 4200000, 4900000, 5600000, 6300000,
];

const REMAKE_WAVES = [
  [2, "Two alien leaders with ring followers"],
  [3, "Huge green zombie"],
  [4, "12 random blue spiders"],
  [5, "4 weak lizard dens"],
  [6, "4 Deadly Fast aliens"],
  [7, "8 jerky spiders"],
  [8, "Spider Boss"],
  [9, "Spideroid"],
  [10, "8 Plasma Shooter spiders"],
  [11, "12 Plasma Shooter spiders"],
  [12, "Zombie boss"],
  [13, "2 Spider Bosses and 8 Plasma Shooters"],
  [14, "2 Spideroids"],
  [15, "2 emerald beetles"],
  [16, "2 Spider Bosses"],
  [17, "2 ancient beetles"],
  [18, "5 Spider Bosses"],
  [19, "3 ancient beetles"],
  [20, "4 ancient beetles"],
];

function milestoneData() {
  const rows = CLASSIC_WAVES.map(([level, wave]) => ({
    series: "Classic", xp: classicLevelXp(level), trigger: `Level ${level}`, wave,
  }));
  for (const [stage, wave] of REMAKE_WAVES) {
    const xp = REMAKE_STAGE_XP[stage];
    rows.push({ series: "Remake", xp, trigger: `Stage ${stage}`, wave });
    rows.push({ series: "Blitz", xp: Math.ceil((xp - 10000) / 1.75), trigger: `Stage ${stage}`, wave });
  }
  return rows;
}

// Creatures per wall-clock second at time t (seconds), one player at 60 fps.
function spawnTick(t) {
  const raw = 500 - Math.floor((t * 1000) / 1800);
  if (raw >= 1) return { count: 1, interval: raw };
  const extra = (1 - raw) >> 1;
  return { count: 1 + extra, interval: Math.max(1, raw + 2 * extra) };
}

function spawnData() {
  const rows = [];
  for (let t = 0; t <= 1080; t += 2) {
    const { count, interval } = spawnTick(t);
    const minute = t / 60;
    rows.push({ x: minute, series: "Classic", y: (count * 1000) / interval });
    rows.push({ x: minute, series: "Remake", y: count * Math.min(60, (60 * 16) / interval) });
    rows.push({ x: minute, series: "Blitz", y: count * Math.min(60, (60 * 25) / interval) });
  }
  return rows;
}

function levelData() {
  const rows = [];
  for (let level = 2; level <= 30; level++) {
    rows.push({ x: level, series: "Classic", y: classicLevelXp(level) });
    rows.push({ x: level, series: "Remake", y: remakeLevelXp(level) });
  }
  return rows;
}

// Average edge spawn: size 53.5, mean random rolls.
function healthData() {
  const rows = [];
  for (let e = 4; e <= 6.85; e += 0.025) {
    const xp = Math.pow(10, e);
    const late = Math.max(0, xp - 2e5) + Math.max(0, xp - 1e6) + Math.max(0, xp - 2e6);
    rows.push({ x: xp, series: "Classic", y: 0.00125 * xp + 59.5 });
    rows.push({ x: xp, series: "Remake", y: (53.5 / 64) * (56 + 0.00125 * xp + 0.002 * late) });
  }
  return rows;
}

function speedData() {
  const rows = [];
  for (let xp = 0; xp <= 600000; xp += 4000) {
    const step = Math.floor(xp / 4000);
    rows.push({ x: xp, series: "Classic", y: Math.min(3.5, step * 0.045 + 0.9) });
    rows.push({ x: xp, series: "Remake", y: Math.min(4.0, step * 0.03 + 0.9) });
  }
  return rows;
}

// ---- specs ----

function axis(dark, extra = {}) {
  return {
    labelColor: dark ? "#aaa" : "#666",
    titleColor: dark ? "#aaa" : "#666",
    gridColor: dark ? "#333" : "#e0e0e0",
    ...extra,
  };
}

function colorScale(dark, domain) {
  const colors = seriesColors(dark);
  return { domain, range: domain.map((name) => colors[SERIES.indexOf(name)]) };
}

function baseSpec(dark, height) {
  return {
    $schema: "https://vega.github.io/schema/vega-lite/v6.json",
    width: "container",
    height,
    background: "transparent",
    config: {
      view: { stroke: null },
      axis: { domainColor: dark ? "#555" : "#ccc" },
      legend: { labelColor: dark ? "#ccc" : "#444", orient: "top" },
    },
  };
}

function lineSpec({ data, height = 260, x, y, series, dash = [] }) {
  const dark = isDark();
  const legend = { title: null };
  const color = { field: "series", type: "nominal", scale: colorScale(dark, series), sort: series, legend };
  return {
    ...baseSpec(dark, height),
    data: { values: data },
    encoding: {
      x: { field: "x", type: "quantitative", title: x.title, scale: x.scale, axis: axis(dark, x.axis) },
    },
    layer: [
      {
        mark: { type: "line", strokeWidth: 2, interpolate: x.step ? "step-after" : "linear", clip: true },
        encoding: {
          y: { field: "y", type: "quantitative", title: y.title, scale: y.scale, axis: axis(dark, y.axis) },
          color,
          strokeDash: {
            field: "series", type: "nominal", sort: series, legend,
            scale: { domain: series, range: series.map((name) => (dash.includes(name) ? [6, 4] : [1, 0])) },
          },
        },
      },
      {
        transform: [{ pivot: "series", value: "y", groupby: ["x"] }],
        mark: { type: "rule", color: dark ? "#666" : "#bbb" },
        encoding: {
          opacity: { condition: { value: 1, param: "hover", empty: false }, value: 0 },
          tooltip: [
            { field: "x", type: "quantitative", title: x.title, format: x.format },
            ...series.map((name) => ({ field: name, type: "quantitative", format: y.format })),
          ],
        },
        params: [{ name: "hover", select: { type: "point", fields: ["x"], nearest: true, on: "pointerover", clear: "pointerout" } }],
      },
    ],
  };
}

function milestoneSpec() {
  const dark = isDark();
  return {
    ...baseSpec(dark, 150),
    data: { values: milestoneData() },
    mark: { type: "point", filled: true, size: 90, opacity: 1, stroke: dark ? "#1e1e1e" : "#fff", strokeWidth: 1.5 },
    encoding: {
      x: {
        field: "xp", type: "quantitative", title: "XP (log scale)",
        scale: { type: "log", domain: [2000, 7000000] }, axis: axis(dark, { format: "~s", values: [3e3, 1e4, 3e4, 1e5, 3e5, 1e6, 3e6] }),
      },
      y: { field: "series", type: "nominal", sort: SERIES, title: null, axis: axis(dark, { grid: false, domain: false, ticks: false }) },
      color: { field: "series", type: "nominal", scale: colorScale(dark, SERIES), legend: null },
      tooltip: [
        { field: "series", title: "Mode" },
        { field: "trigger", title: "Trigger" },
        { field: "xp", type: "quantitative", title: "XP", format: "," },
        { field: "wave", title: "Wave" },
      ],
    },
  };
}

const WIDGETS = {
  "survival-spawn-rate": () => lineSpec({
    data: spawnData(),
    height: 280,
    series: SERIES,
    dash: ["Blitz"],
    x: { title: "minutes", format: ".1f", scale: { domain: [0, 18], nice: false } },
    y: { title: "creatures per second", format: ",.1f", scale: { type: "log", domain: [1, 10000] }, axis: { format: "~s", values: [1, 10, 100, 1000, 10000] } },
  }),
  "survival-milestones": milestoneSpec,
  "survival-levels": () => lineSpec({
    data: levelData(),
    series: ["Classic", "Remake"],
    x: { title: "level", format: "d", step: true },
    y: { title: "XP to reach level", format: ",", scale: { type: "log" }, axis: { format: "~s", values: [1e3, 1e4, 1e5, 1e6, 1e7, 1e8] } },
  }),
  "survival-creature-health": () => lineSpec({
    data: healthData(),
    height: 220,
    series: ["Classic", "Remake"],
    x: { title: "XP (log scale)", format: ",.0f", scale: { type: "log", domain: [10000, 7000000] }, axis: { format: "~s", values: [1e4, 1e5, 1e6] } },
    y: { title: "health", format: ",.0f", scale: { type: "log" }, axis: { format: "~s", values: [10, 100, 1e3, 1e4, 1e5] } },
  }),
  "survival-creature-speed": () => lineSpec({
    data: speedData(),
    height: 220,
    series: ["Classic", "Remake"],
    x: { title: "XP", format: ",", step: true, axis: { format: "~s" } },
    y: { title: "move speed", format: ".2f", scale: { domain: [0, 4.5] } },
  }),
};

function initSurvivalCompare() {
  for (const [name, spec] of Object.entries(WIDGETS)) {
    const container = document.querySelector(`[data-widget="${name}"]:not([data-init])`);
    if (!container) continue;
    container.setAttribute("data-init", "");
    container.className = "chart-widget";
    const chart = document.createElement("div");
    chart.className = "chart-widget-plot";
    container.append(chart);
    vegaEmbed(chart, spec(), { actions: false, renderer: "svg" });
  }
}

// support instant navigation
if (typeof document$ !== "undefined") {
  document$.subscribe(initSurvivalCompare);
} else {
  document.addEventListener("DOMContentLoaded", initSurvivalCompare);
}
