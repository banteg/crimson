import { siDiscord, siGithub, siX } from "simple-icons";
import { For, Show } from "solid-js";
import type { PlayerView } from "../../src/api-types";
import { PROVIDER_LABELS, playerParts } from "./names";

export { PROVIDER_LABELS };

const ICONS = { github: siGithub, discord: siDiscord, x: siX };

function Icon(props: { provider: keyof typeof ICONS }) {
  const icon = ICONS[props.provider];
  return (
    <svg class="icon" viewBox="0 0 24 24" role="img" aria-label={icon.title}>
      <path d={icon.path} />
    </svg>
  );
}

export function PlayerName(props: { player: PlayerView; heading?: boolean }) {
  const parts = () => playerParts(props.player);
  return (
    <>
      <Show when={parts().avatar}>{(avatar) => <img class={`avatar${props.heading ? " heading" : ""}`} src={avatar()} alt="" />}</Show>
      <a class="name" classList={{ unnamed: parts().unnamed }} href={`/players/${props.player.id}`}>
        {parts().label}
      </a>
      <Show when={parts().fingerprint}>{(fingerprint) => <span class="muted"> · {fingerprint()}</span>}</Show>
      <Show when={parts().links.length}>
        <span class="links">
          <Show when={parts().handle}>{(handle) => <span class="muted handle">{handle()}</span>}</Show>
          <For each={parts().links}>
            {({ link, handle }) => (
              <a class="provider" href={link.url} title={`${PROVIDER_LABELS[link.provider]} ${link.handle}`} target="_blank" rel="noopener">
                <Icon provider={link.provider} />
                {handle ? ` ${handle}` : ""}
              </a>
            )}
          </For>
        </span>
      </Show>
    </>
  );
}
