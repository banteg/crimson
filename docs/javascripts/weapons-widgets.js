// Direct-hit multipliers, grouped by the projectile each weapon actually fires.
// Rockets and flamers don't use the bullet formula, so they're left out.
const SHOTS = [
  { name: "Pistol, Mean Minigun", multiplier: 4.1 },
  { name: "Assault Rifle, Submachine Gun, Pulse Gun", multiplier: 1.0 },
  { name: "Shotgun, Sawed-off, Jackhammer pellet", multiplier: 1.2 },
  { name: "Plasma Rifle, Multi-Plasma inner bolt", multiplier: 5.0 },
  { name: "Plasma Minigun, Plasma Shotgun pellet, Multi-Plasma outer bolt", multiplier: 2.1 },
  { name: "Ion Rifle direct hit", multiplier: 3.0 },
  { name: "Ion Minigun, Ion Shotgun pellet direct hit", multiplier: 1.4 },
  { name: "Ion Cannon direct hit", multiplier: 16.7 },
  { name: "Plasma Cannon", multiplier: 28.0 },
  { name: "Splitter Gun", multiplier: 6.0 },
  { name: "Shrinkifier 5k", multiplier: 0.0 },
  { name: "Blade Gun last hit", multiplier: 11.0 },
  { name: "Gauss Gun, Gauss Shotgun last hit", multiplier: 1.0 },
  { name: "Fire Bullets last hit", multiplier: 0.25 },
];

// Piercing shots: pool and the multiplier of their last, normal hit.
const POOL_WEAPONS = [
  { name: "Gauss Gun", pool: 300, multiplier: 1.0, trail: "51, 128, 255" },
  { name: "Fire Bullets", pool: 240, multiplier: 0.25, trail: "255, 153, 26" },
  { name: "Blade Gun", pool: 50, multiplier: 11.0, trail: "240, 120, 255" },
];

const MAX_ENEMIES = 6;

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
    SHOTS,
    (_, i) => i,
    (w) => `${w.name} (${w.multiplier}x)`,
  );

  controls.append(select);

  const chartDiv = document.createElement("div");
  chartDiv.className = "damage-chart";

  let view;

  function update() {
    const weapon = SHOTS[Number(select.value)];
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

  function formatPool(value) {
    return value >= 10000 ? `${Math.round(value / 1000)}k` : `${Math.round(value)}`;
  }

  // Simulates one shot through a line of identical enemies, without damage perks.
  // Each hit spends 1 from the pool and deals the rest; the pool then becomes
  // that damage minus the target's remaining health (overkill counts back in).
  // A spent shot lands one last normal hit on the next contact and stops.
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
    let reached = 0;
    let lastHitOn = -1;
    let kills = 0;

    for (let i = 0; i < MAX_ENEMIES && lastHitOn === -1; i++) {
      reached++;
      let hp = enemy.hp;
      const poolLabel = document.createElement("div");
      poolLabel.className = "pool-cell";

      if (pool <= 0) {
        poolLabel.textContent = "last";
        lastHitOn = i;
      } else {
        poolLabel.textContent = formatPool(pool);
        while (hp > 0 && pool > 0) {
          pool -= 1;
          if (pool <= 0) break;
          hp -= pool;
          pool -= hp;
        }
        if (hp > 0) lastHitOn = i;
      }
      poolRow.appendChild(poolLabel);

      const killed = hp <= 0;
      if (killed) kills++;
      const sprite = document.createElement("img");
      sprite.src = killed ? `/images/creatures/${enemy.sprite}-dead.png` : `/images/creatures/${enemy.sprite}.png`;
      sprite.alt = enemy.name;
      sprite.className = "pool-sprite";
      spriteRow.appendChild(sprite);

      const hpLabel = document.createElement("div");
      hpLabel.className = "pool-cell";
      if (!killed) hpLabel.textContent = `${Math.round(hp)}`;
      hpRow.appendChild(hpLabel);
    }

    const trail = document.createElement("div");
    trail.className = "pool-trail";
    const c = weapon.trail;
    trail.style.width = `calc(${reached * 32 - 16}px + 1rem)`;
    trail.style.background = `linear-gradient(to right, rgba(${c}, 0.25), rgba(${c}, 0.8))`;

    const lastHit = Math.round(calcDamage(50, weapon.multiplier));
    const caption = document.createElement("div");
    caption.style.fontSize = "0.7rem";
    caption.textContent = lastHitOn === -1
      ? `${enemy.name} (${enemy.hp} HP): still going after ${kills} kills, pool ${formatPool(pool)}`
      : `${enemy.name} (${enemy.hp} HP): ${kills} kills, then one last normal hit (up to ${lastHit})`;

    row.append(caption, poolRow, spriteRow, hpRow);
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
