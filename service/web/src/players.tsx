import { siDiscord, siGithub, siX } from "simple-icons";
import { For, Show } from "solid-js";
import type { Pilot, PlayerView, SeatView } from "../../src/api-types";
import { DELETED_PLAYER, PROVIDER_LABELS, playerParts } from "./names";

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

// `tag` shows the bot tag of an account that plays as a bot; a bot board says so already.
export function PlayerName(props: { player: PlayerView; heading?: boolean; tag?: boolean }) {
  const parts = () => playerParts(props.player);
  return (
    <>
      <Show when={parts().avatar}>{(avatar) => <img class={`avatar${props.heading ? " heading" : ""}`} src={avatar()} alt="" />}</Show>
      <a class="name" classList={{ unnamed: parts().unnamed }} href={`/players/${props.player.id}`}>
        {parts().label}
      </a>
      <Show when={parts().fingerprint}>{(fingerprint) => <span class="muted"> · {fingerprint()}</span>}</Show>
      <Show when={props.player.bot && props.tag !== false}>
        <span class="tag" title="This account's runs are on the bot boards">bot</span>
      </Show>
      <Show when={parts().links.length}>
        <span class="links">
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

// Who played a run: its player, or a co-op run's players by seat, "A & B".
export function RunPlayers(props: { player: PlayerView; team: SeatView[] | null; heading?: boolean; tag?: boolean }) {
  return (
    <Show when={props.team} fallback={<PlayerName player={props.player} heading={props.heading} tag={props.tag} />}>
      {(team) => (
        <For each={team()}>
          {(seat, i) => (
            <>
              <Show when={i()}>{" & "}</Show>
              <Show when={seat.player} fallback={<span class="muted">{DELETED_PLAYER}</span>}>
                {(player) => <PlayerName player={player()} heading={props.heading} tag={props.tag} />}
              </Show>
            </>
          )}
        </For>
      )}
    </Show>
  );
}

// The program that played a run, as its operator declares it.
export function PilotName(props: { pilot: Pilot }) {
  return (
    <span class="pilot" title="Declared by the run's operator">
      <Show when={props.pilot.url} fallback={props.pilot.name}>
        <a href={props.pilot.url} target="_blank" rel="noopener">
          {props.pilot.name}
        </a>
      </Show>
      <Show when={props.pilot.model}>
        <span class="muted"> ({props.pilot.model})</span>
      </Show>
    </span>
  );
}
