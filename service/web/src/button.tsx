import { onMount } from "solid-js";

// The game's button plates (ui_button_64x32 and ui_button_128x32) at the widths the game stretches them to, and how far
// the label keeps from each end: the glass starts 12 px in, and the label keeps 4 px off its edge.
const PLATES = [82, 145];
const MARGIN = 16;

// The smallest plate that holds the label, shared by every button in a `.buttons` row so the row lines up.
function fit(button: HTMLElement) {
  const row = button.closest(".buttons");
  const members = row ? [...row.querySelectorAll<HTMLElement>(".button")] : [button];
  const label = Math.max(...members.map((member) => member.querySelector("span")!.offsetWidth));
  const plate = PLATES.find((width) => label + 2 * MARGIN <= width) ?? PLATES.at(-1)!;
  for (const member of members) member.classList.toggle("wide", plate > PLATES[0]!);
}

// ui_button_update's look: the label at 70% white, full on hover, over a blue-grey fill that fades in under the glass.
// A link with `href`, else a button; `native` links leave the app (server routes such as an OAuth start).
export function GameButton(props: { label: string; href?: string; native?: boolean; on?: boolean; danger?: boolean; onClick?: () => void }) {
  let button!: HTMLElement;
  onMount(() => void document.fonts.ready.then(() => fit(button)));
  const classes = () => ({ on: props.on ?? false, danger: props.danger ?? false });
  return props.href === undefined ? (
    <button ref={(el) => (button = el)} type="button" class="button" classList={classes()} onClick={() => props.onClick?.()}>
      <span>{props.label}</span>
    </button>
  ) : (
    <a ref={(el) => (button = el)} class="button" classList={classes()} href={props.href} data-native={props.native ? "" : undefined}>
      <span>{props.label}</span>
    </a>
  );
}
