// A quest's final time (src/crimson/quests/results.py compute_quest_final_time): the quest time less a life bonus and
// a second for each unpicked perk, an exactly zero result recorded as 1 ms. The verifier derives it; run pages break
// it down.

// The life bonus, from each player's health, player one first: player one's health is truncated before the f32
// product with 50, which is then exact; a partner's product is rounded to f32, then truncated.
export function lifeBonusMs(health: number[], preserveBugs = false): number {
  return health.reduce((sum, hp, i) => {
    const h = preserveBugs ? hp : Math.max(0, hp);
    return sum + Math.trunc(i === 0 ? Math.trunc(h) * 50 : Math.fround(h * 50));
  }, 0);
}

export function questFinalMs(base: number, health: number[], pending: number, preserveBugs = false): number {
  const final = base - lifeBonusMs(health, preserveBugs) - pending * 1000;
  return final === 0 ? 1 : final;
}
