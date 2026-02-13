const WEAPONS = [
  { id: 1, name: "Pistol", multiplier: 4.1 },
  { id: 2, name: "Assault Rifle", multiplier: 1.0 },
  { id: 3, name: "Shotgun", multiplier: 1.2 },
  { id: 4, name: "Sawed-off Shotgun", multiplier: 1.0 },
  { id: 5, name: "Submachine Gun", multiplier: 1.0 },
  { id: 6, name: "Gauss Gun", multiplier: 1.0 },
  { id: 7, name: "Mean Minigun", multiplier: 1.0 },
  { id: 8, name: "Flamethrower", multiplier: 1.0 },
  { id: 9, name: "Plasma Rifle", multiplier: 5.0 },
  { id: 10, name: "Multi-Plasma", multiplier: 1.0 },
  { id: 11, name: "Plasma Minigun", multiplier: 2.1 },
  { id: 12, name: "Rocket Launcher", multiplier: 1.0 },
  { id: 13, name: "Seeker Rockets", multiplier: 1.0 },
  { id: 14, name: "Plasma Shotgun", multiplier: 1.0 },
  { id: 15, name: "Blow Torch", multiplier: 1.0 },
  { id: 17, name: "Mini-Rocket Swarmers", multiplier: 1.0 },
  { id: 18, name: "Rocket Minigun", multiplier: 1.0 },
  { id: 19, name: "Pulse Gun", multiplier: 1.0 },
  { id: 20, name: "Jackhammer", multiplier: 1.0 },
  { id: 21, name: "Ion Rifle", multiplier: 3.0 },
  { id: 22, name: "Ion Minigun", multiplier: 1.4 },
  { id: 23, name: "Ion Cannon", multiplier: 16.7 },
  { id: 24, name: "Shrinkifier 5k", multiplier: 0.0 },
  { id: 25, name: "Blade Gun", multiplier: 11.0 },
  { id: 28, name: "Plasma Cannon", multiplier: 28.0 },
  { id: 29, name: "Splitter Gun", multiplier: 6.0 },
  { id: 30, name: "Gauss Shotgun", multiplier: 1.0 },
  { id: 31, name: "Ion Shotgun", multiplier: 1.0 },
];

const POOL_WEAPONS = [
  { name: "Gauss Gun", pool: 300, trail: "51, 128, 255" },
  { name: "Fire Bullets", pool: 240, trail: "255, 153, 26" },
  { name: "Blade Gun", pool: 50, trail: "240, 120, 255" },
];

const ENEMIES = [
  { name: "Small alien", hp: 20, sprite: "alien" },
  { name: "Lizard", hp: 55, sprite: "lizard" },
  { name: "Spider", hp: 70, sprite: "spider" },
  { name: "Zombie", hp: 200, sprite: "zombie" },
  { name: "Big spider", hp: 1000, sprite: "big-spider" },
];

function calcDamage(distance, multiplier) {
  return ((100 / distance) * multiplier * 30 + 10) * 0.95;
}

function generateFalloffData(multiplier) {
  const data = [];
  for (let d = 50; d <= 500; d += 5) {
    data.push({ distance: d, damage: Math.round(calcDamage(d, multiplier) * 10) / 10 });
  }
  return data;
}

function isDarkMode() {
  return document.body.dataset.mdColorScheme === "slate";
}

function falloffSpec(multiplier) {
  const dark = isDarkMode();
  return {
    $schema: "https://vega.github.io/schema/vega-lite/v6.json",
    width: "container",
    height: 200,
    padding: { top: 10, left: 5, right: 5, bottom: 5 },
    background: "transparent",
    data: { values: generateFalloffData(multiplier) },
    mark: { type: "line", strokeWidth: 2, tooltip: true, clip: false },
    encoding: {
      x: {
        field: "distance",
        type: "quantitative",
        title: "distance",
        scale: { domain: [50, 500] },
        axis: { labelColor: dark ? "#aaa" : "#666", titleColor: dark ? "#aaa" : "#666", gridColor: dark ? "#333" : "#e0e0e0" },
      },
      y: {
        field: "damage",
        type: "quantitative",
        title: "damage",
        scale: { zero: true, nice: true },
        axis: { labelColor: dark ? "#aaa" : "#666", titleColor: dark ? "#aaa" : "#666", gridColor: dark ? "#333" : "#e0e0e0" },
      },
    },
    config: {
      view: { stroke: null },
      axis: { domainColor: dark ? "#555" : "#ccc" },
    },
  };
}

function buildSelect(options, valueFn, labelFn) {
  const select = document.createElement("select");
  options.forEach((opt, i) => {
    const el = document.createElement("option");
    el.value = valueFn(opt, i);
    el.textContent = labelFn(opt, i);
    select.appendChild(el);
  });
  return select;
}

function initDamageCalculator(container) {
  container.className = "weapon-widget";

  const controls = document.createElement("div");
  controls.className = "widget-controls";

  const select = buildSelect(
    WEAPONS,
    (w) => w.id,
    (w) => `${w.name} (${w.multiplier}x)`,
  );

  controls.append(select);

  const chartDiv = document.createElement("div");
  chartDiv.className = "damage-chart";

  let view;

  function update() {
    const weapon = WEAPONS.find((w) => w.id === Number(select.value));
    const spec = falloffSpec(weapon.multiplier);
    if (view) view.finalize();
    vegaEmbed(chartDiv, spec, { actions: false, renderer: "svg" }).then((result) => {
      view = result.view;
    });
  }

  select.addEventListener("change", update);
  container.append(controls, chartDiv);
  update();
}

function initDamagePool(container) {
  container.className = "weapon-widget";

  const controls = document.createElement("div");
  controls.className = "widget-controls";

  const select = buildSelect(
    POOL_WEAPONS,
    (_, i) => i,
    (w) => `${w.name} (pool ${w.pool})`,
  );

  controls.append(select);

  const rows = document.createElement("div");
  rows.className = "pool-rows";

  function renderRow(weapon, enemy) {
    const row = document.createElement("div");
    row.className = "pool-viz";

    const poolRow = document.createElement("div");
    poolRow.className = "pool-label-row";
    const spriteRow = document.createElement("div");
    spriteRow.className = "pool-sprite-row";
    const hpRow = document.createElement("div");
    hpRow.className = "pool-hp-row";

    let pool = weapon.pool;
    let drained = false;
    let hitCount = 0;
    const maxEnemies = Math.ceil(weapon.pool / enemy.hp) + 1;

    for (let i = 0; i < maxEnemies; i++) {
      const hit = pool > 0;
      const dealt = hit ? Math.min(pool, enemy.hp) : 0;
      const remaining = enemy.hp - dealt;
      const killed = hit && remaining === 0;
      if (hit) hitCount++;

      const poolLabel = document.createElement("div");
      poolLabel.className = "pool-cell";
      if (hit) {
        poolLabel.textContent = `${pool}`;
      } else if (!drained) {
        poolLabel.textContent = "0";
        drained = true;
      }
      poolRow.appendChild(poolLabel);

      const sprite = document.createElement("img");
      sprite.src = killed ? `/images/creatures/${enemy.sprite}-dead.png` : `/images/creatures/${enemy.sprite}.png`;
      sprite.alt = enemy.name;
      sprite.className = "pool-sprite";
      spriteRow.appendChild(sprite);

      const hpLabel = document.createElement("div");
      hpLabel.className = "pool-cell";
      if (!killed) hpLabel.textContent = `${remaining}`;
      hpRow.appendChild(hpLabel);

      if (hit) pool = Math.max(0, pool - enemy.hp);
    }

    const trail = document.createElement("div");
    trail.className = "pool-trail";
    const c = weapon.trail;
    trail.style.width = `calc(${hitCount * 32 - 16}px + 1rem)`;
    trail.style.background = `linear-gradient(to right, rgba(${c}, 0.25), rgba(${c}, 0.8))`;

    row.append(poolRow, spriteRow, hpRow);
    spriteRow.appendChild(trail);
    return row;
  }

  function update() {
    const weapon = POOL_WEAPONS[Number(select.value)];
    rows.innerHTML = "";
    for (const enemy of ENEMIES) {
      rows.appendChild(renderRow(weapon, enemy));
    }
  }

  select.addEventListener("change", update);
  container.append(controls, rows);
  update();
}

function initWidgets() {
  const calc = document.querySelector('[data-widget="damage-calculator"]:not([data-init])');
  if (calc) { calc.setAttribute("data-init", ""); initDamageCalculator(calc); }

  const pool = document.querySelector('[data-widget="damage-pool"]:not([data-init])');
  if (pool) { pool.setAttribute("data-init", ""); initDamagePool(pool); }
}

// support instant navigation (MkDocs Material)
if (typeof document$ !== "undefined") {
  document$.subscribe(initWidgets);
} else {
  document.addEventListener("DOMContentLoaded", initWidgets);
}
