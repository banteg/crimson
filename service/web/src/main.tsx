import { createSignal, For, Show } from "solid-js";
import { render } from "solid-js/web";
import { type Navigator, resolve, type Screen } from "./pages";
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

function App() {
  const [screen, setScreen] = createSignal<Screen | null>(null);
  const [leaving, setLeaving] = createSignal(false);
  const [grounds, setGrounds] = createSignal<Layer[]>([]);
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

  async function go(path: string, history_: "push" | "replace" | "none", animate = true) {
    const id = ++navigation;
    const url = new URL(path, location.href);
    if (history_ === "push") history.pushState(null, "", url);
    else if (history_ === "replace") history.replaceState(null, "", url);
    const current = screen();
    const out = animate && motion() && current ? SLIDE_MS + (current.panels.length - 1) * STAGGER_MS : 0;
    if (out) setLeaving(true);
    const [next] = await Promise.all([
      resolve(url, nav).catch(() => ({ title: "Error", quest: null, panels: [() => <p>The leaderboard could not be reached.</p>] })),
      sleep(out),
    ]);
    if (id !== navigation) return;
    document.title = next.title ? `${next.title} · crimson.land` : "crimson.land";
    if (animate) window.scrollTo(0, 0);
    setScreen(next);
    setLeaving(false);
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
    <div class="screen" classList={{ leaving: leaving() }}>
      <For each={grounds()}>
        {(layer) => <div class="ground" style={{ "background-image": `url(${layer.url})`, "background-size": `1024px ${layer.height}px` }} />}
      </For>
      <header>
        <a href="/">
          <img src="/ui/sign.png" width="512" height="128" alt="Crimsonland" />
        </a>
      </header>
      <main>
        <Show when={screen()}>
          {(current) => (
            <For each={current().panels}>
              {(panel, i) => (
                <section class="panel" style={{ "--i": i(), "--n": current().panels.length }}>
                  {panel()}
                </section>
              )}
            </For>
          )}
        </Show>
      </main>
      <footer>
        <a href="/">Boards</a> · <a href="/quests/1">Quests</a> · <a href="/about">About</a> · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> ·{" "}
        <a href="https://github.com/banteg/crimson">GitHub</a>
      </footer>
    </div>
  );
}

render(() => <App />, document.getElementById("app")!);
