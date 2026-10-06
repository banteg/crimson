import { type Accessor, createSignal, For, onMount, type Setter, Show } from "solid-js";
import { render } from "solid-js/web";
import { get } from "./api";
import { type Navigator, type Panel, resolve, type Screen } from "./pages";
import "./style.css";
import { drawGround } from "./terrain/draw";

// The game's menu timeline (src/crimson/ui/animation.py ui_element_anim): each panel slides in from the left over
// 300 ms, starting 100 ms after the one before, and the timeline runs backwards to slide them out first.
const SLIDE_MS = 300;
const STAGGER_MS = 100;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const motion = () => !window.matchMedia("(prefers-reduced-motion: reduce)").matches;

interface Layer {
  id: number;
  url: string;
  height: number;
}

// A panel on screen: its content, its place in the slide-in order, and its place in the slide-out order while it leaves.
interface Shown {
  key: string | undefined;
  panel: Accessor<Panel>;
  setPanel: Setter<Panel>;
  enter: number;
  out: Accessor<number | null>;
  setOut: Setter<number | null>;
}

function shown(panel: Panel, enter: number): Shown {
  const [current, setPanel] = createSignal<Panel>(panel);
  const [out, setOut] = createSignal<number | null>(null);
  return { key: panel.key, panel: current, setPanel, enter, out, setOut };
}

// Slide panels out, the last one first, and resolve once the last of them is gone.
function slideOut(panels: Shown[]): number {
  panels.forEach((panel, i) => panel.setOut(panels.length - 1 - i));
  return panels.length ? SLIDE_MS + (panels.length - 1) * STAGGER_MS : 0;
}

const MENU: { label: string; href: string; on: (path: string) => boolean }[] = [
  { label: "Survival", href: "/boards/survival", on: (path) => path === "/boards/survival" },
  { label: "Quests", href: "/quests/1", on: (path) => /^\/(?:boards\/)?quests/.test(path) },
  { label: "About", href: "/about", on: (path) => path === "/about" },
];

// ui_button_update: a 64x32 plate stretched to 82 px under 40 px of label, else the 128x32 one at 145 px; the label
// at 70% white, full on hover, over a blue-grey fill that fades in under the plate's glass.
// The game draws the label's cell 10 px down, its capitals 2 px below the glass's middle; here they sit on it.
function MenuButton(props: { label: string; href: string; on: boolean }) {
  const [wide, setWide] = createSignal(false);
  let label!: HTMLSpanElement;
  onMount(() => void document.fonts.ready.then(() => setWide(label.offsetWidth >= 40)));
  return (
    <a class="button" classList={{ wide: wide(), on: props.on }} href={props.href}>
      <span ref={label}>{props.label}</span>
    </a>
  );
}

function App() {
  const [panels, setPanels] = createSignal<Shown[]>([]);
  const [grounds, setGrounds] = createSignal<Layer[]>([]);
  const [path, setPath] = createSignal(location.pathname);
  const [me, setMe] = createSignal<number | null>(null);
  let navigation = 0;
  let groundKey: string | null = null;
  // Pages without a quest keep one random ground for the visit; a reload rolls a new one, as the game does.
  let randomGround: ReturnType<typeof drawGround> | null = null;

  // A quest's board shows a fresh ground of that quest; the new ground fades in over the old one.
  async function showGround(quest: string | null) {
    const key = quest ?? "random";
    if (key === groundKey) return;
    groundKey = key;
    const ground = await (quest ? drawGround(quest) : (randomGround ??= drawGround(null)));
    if (groundKey !== key) return;
    setGrounds((layers) => [...layers.slice(-1), { id: navigation * 1000 + layers.length, ...ground }]);
  }

  // Unkeyed panels start leaving at once; a keyed one waits for the next screen, and stays if it is there in the same
  // place.
  async function go(path: string, history_: "push" | "replace" | "none", animate = true) {
    const id = ++navigation;
    const url = new URL(path, location.href);
    if (history_ === "push") history.pushState(null, "", url);
    else if (history_ === "replace") history.replaceState(null, "", url);
    setPath(url.pathname);
    void get<{ account: number | null }>("/api/me").then((answer) => setMe(answer!.account));
    const moving = animate && motion();
    const old = panels();
    const started = performance.now();
    const early = moving ? slideOut(old.filter((panel) => panel.key === undefined)) : 0;
    const next = await resolve(url, nav).catch(
      (): Screen => ({ title: "Error", quest: null, panels: [() => <p>The leaderboard could not be reached.</p>] }),
    );
    if (id !== navigation) return;
    const stays = (panel: Shown, i: number) => panel.key !== undefined && next.panels[i]?.key === panel.key;
    const late = moving ? slideOut(old.filter((panel, i) => panel.key !== undefined && !stays(panel, i))) : 0;
    await sleep(Math.max(early - (performance.now() - started), late));
    if (id !== navigation) return;
    document.title = next.title ? `${next.title} · crimson.land` : "crimson.land";
    if (animate) window.scrollTo(0, 0);
    let entering = 0;
    setPanels(
      next.panels.map((panel, i) => {
        const kept = old[i];
        if (!kept || !stays(kept, i)) return shown(panel, entering++);
        kept.setPanel(() => panel);
        kept.setOut(null);
        return kept;
      }),
    );
    void showGround(next.quest);
  }

  const here = () => location.pathname + location.search;
  const nav: Navigator = {
    go: (path, replace) => void go(path, replace ? "replace" : "push"),
    reload: () => void go(here(), "none", false),
  };

  document.addEventListener("click", (event) => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const link = (event.target as Element).closest("a");
    if (!link || link.target || link.hasAttribute("data-native") || link.origin !== location.origin) return;
    event.preventDefault();
    if (link.pathname + link.search !== here()) void go(link.pathname + link.search, "push");
  });
  window.addEventListener("popstate", () => void go(here(), "none"));
  void go(here(), "none");

  return (
    <div class="screen">
      <For each={grounds()}>
        {(layer) => <div class="ground" style={{ "background-image": `url(${layer.url})`, "background-size": `1024px ${layer.height}px` }} />}
      </For>
      <header>
        <nav class="menu">
          <For each={MENU}>{(item) => <MenuButton label={item.label} href={item.href} on={item.on(path())} />}</For>
          <Show when={me()}>{(id) => <MenuButton label="Profile" href={`/players/${id()}`} on={path() === `/players/${id()}`} />}</Show>
        </nav>
        <a class="sign" href="/">
          <img src="/ui/sign.png" width="512" height="128" alt="Crimsonland" />
        </a>
      </header>
      <main>
        <For each={panels()}>
          {(shown) => (
            <section class="panel" classList={{ leaving: shown.out() !== null }} style={{ "--in": shown.enter, "--out": shown.out() ?? 0 }}>
              {shown.panel()()}
            </section>
          )}
        </For>
      </main>
      <footer>
        <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> · <a href="https://github.com/banteg/crimson">GitHub</a>
      </footer>
    </div>
  );
}

render(() => <App />, document.getElementById("app")!);
