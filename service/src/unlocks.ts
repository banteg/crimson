// The quests a ranked run's save has unlocked, as [normal, hardcore] (src/crimson/replay/ranked.py ranked_status).
// Survival plays with every quest done in both difficulties. A quest plays on the save that has just unlocked it: a
// normal quest with the quests before it done, a hardcore quest with the whole normal campaign and the hardcore
// quests before it.

const QUEST_COUNT = 50;
const QUESTS_PER_STAGE = 10;

export function rankedUnlocks(quest: { major: number; minor: number } | null, hardcore: boolean): [number, number] {
  if (quest === null) return [QUEST_COUNT, QUEST_COUNT];
  const index = (quest.major - 1) * QUESTS_PER_STAGE + (quest.minor - 1);
  return hardcore ? [QUEST_COUNT, index] : [index, 0];
}
