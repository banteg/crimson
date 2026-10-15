// Display tokens for quests/dsl/quest.lark, not a second parser. Unmatched text
// stays intact, and the view renders every token as text rather than HTML.
export interface QuestToken {
  text: string;
  kind: "comment" | "string" | "number" | "keyword" | "literal" | "function" | "entity" | null;
}

const KEYWORDS = new Set([
  "quest", "version", "author", "order", "weapon", "terrain", "no_bonuses", "no_perks", "no_weapons", "fixed_weapon",
  "let", "var", "spawn", "at", "copies", "heading", "burst", "place", "on", "break", "repeat", "as", "for", "in",
  "if", "while", "pattern", "elif", "else", "or", "and", "not",
]);
const LITERALS = new Set(["true", "false", "chronological", "as-written"]);

export function questTokens(source: string): QuestToken[] {
  // Consume strings and comments together so a quoted # cannot start a comment.
  const pattern = /"(?:[^"\\\r\n]|\\[^\r\n])*"|#[^\r\n]*|0[xX][\da-fA-F]+|(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?(?:ms|s|deg)?|\bas-written\b|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*/g;
  const tokens: QuestToken[] = [];
  let end = 0;
  for (const match of source.matchAll(pattern)) {
    if (match.index > end) tokens.push({ text: source.slice(end, match.index), kind: null });
    const text = match[0];
    end = match.index + text.length;
    const kind: QuestToken["kind"] = text.startsWith('"') ? "string" : text.startsWith("#") ? "comment"
      : /^[\d.]/.test(text) ? "number" : KEYWORDS.has(text) ? "keyword" : LITERALS.has(text) ? "literal"
      : text.includes(".") ? "entity" : /^[\t ]*\(/.test(source.slice(end)) ? "function" : null;
    tokens.push({ text, kind });
  }
  if (end < source.length) tokens.push({ text: source.slice(end), kind: null });
  return tokens;
}
