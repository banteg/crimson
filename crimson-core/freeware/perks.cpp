// Metadata in original registration order (0x407920); the selection flags are per mode.
#include "game.h"
#include <algorithm>
#include <cmath>
extern freeware::Game *freeware_frame_game;
extern "C" void freeware_grant_perk(int);
namespace freeware {
struct Perk {
  const char *name, *description;
  bool coop;
};
static const Perk perks[] = {
    {"Test perk", "You shouldn't be seeing this..", true},
    {"Bloody Mess",
     "More the merrier. More blood guarantees a better experience. You spill more blood and gain more experience "
     "points.",
     true},
    {"Almost Invisible Man",
     "Your invisibility ability phases in and out, Creatures see less of you when you're more invisible.", true},
    {"Sharpshooter",
     "You are the one who shoots sharps. Miraculously your aiming improves drastically, but you take a little bit "
     "more time on actually firing the gun. If you order now, you also get a fancy LASER SIGHT without ANY "
     "charge!",
     true},
    {"Long Distance Runner",
     "You run like a train that has feet and runs. You just need a bit time to warm up. In other words you'll "
     "move faster the longer you run without stopping.",
     true},
    {"Fastloader", "Man you sure know how to load a gun.", true},
    {"Lean Mean Exp Machine",
     "Why kill for experience when you can make some of your own for free! With this perk the experience just "
     "keeps flowing in at a constant rate.",
     true},
    {"Spontaneously Combusteous",
     "Well you don't light up but you make other burn. Bare aiming at creature causes them to heat up.", true},
    {"Instant Winner", "2500 experience points. Right away. Take it or leave it.", true},
    {"Grim Deal",
     "I'll make you a deal: I give you 6667 experience points, and you give me your life. So you die but propably "
     "score high. Pounder that one.",
     false},
    {"Plaguebearer",
     "You carry a horrible disease. Good for you: you are immune. Bad for them: it is contagious! (Monsters too "
     "become immune over time.)",
     true},
    {"Ammo Maniac",
     "You squeeze and you push and you pack your clips with about 20% more ammo than a regular fellow. They call "
     "you Ammo Maniac with a deep respect in their voices.",
     true},
    {"Radioactive",
     "You are the Radioactive-man, you have that healthy green glow around you. Others don't like it though, it "
     "makes them sick and nauseous whenever near you.",
     true},
    {"Berserk Attack",
     "Every once in a while you go berserk and just start shooting madly at everyone you see with a gun you don't "
     "have. Not only that, but you seem to be invulnerable during these acts of violence. Strange indeed.",
     false},
    {"Fastshot",
     "Funny how you make your gun spit bullets faster than the next guy. Even the most professional of engineers "
     "are astonished.",
     true},
    {"Reflex Boosted",
     "To you the world seems to go on about 5% slower than to an average person. It can be rather irritating "
     "sometimes.",
     true},
    {"Doctor",
     "With a single glance you can tell the medical condition of, well, anyone. Also, being a doctor, you know "
     "exactly what hurts the most..",
     true},
    {"Jinxed", "Things happen near you. Strangest things. Creatures just drop dead and accidents happen. Beware.",
     true},
    {"Evil Eyes", "(aka Ice Gaze) You have really really mean eyes: monsters freeze still as you look at them.",
     true},
    {"Fatal Lottery", "Fifty-fifty chance of dying OR gaining 10k experience points. Interested, anyone?", false},
    {"Weapon perk: Assault rifle", "Here, have this upgraded assault rifle. No questions asked.", false},
    {"Weapon perk: Shotgun", "Here, have this modified shotgun. No questions asked.", false},
    {"Anxious Loader",
     "When you can't stand waiting your gun to be reloaded you can speed up the process by clicking your FIRE "
     "button repeatedly as fast as you can.",
     true},
    {"Final Revenge", "Pick this and you'll get your revenge. It's a promise.", false},
    {"Infernal Contract",
     "In exchance for your soul, a dark stranger is offering you three (3) experience levels. That means three "
     "new perks but no exp.pts. To collect his part of the bargain soon enough, your health is reduced to a "
     "near-death status. Just sign down here below this pentagram..",
     false},
    {"Perk Expert",
     "You sure know how to pick a perk -- most people just don't see those extra two perks laying around. This "
     "gives you the opportunity to pick the freshest and shiniest perks from the top.",
     true},
    {"Corrupted Hint",
     "The message seems to be a bit corrupted though and doesn't necessarely mean anything. (Randomly replaced "
     "letters)",
     true},
    {"Corrupted Hint",
     "The message seems to be a bit corrupted though and doesn't necessarely mean anything. (Randomly replaced "
     "letters)",
     true},
    {"Corrupted Hint",
     "The message seems to be a bit corrupted though and doesn't necessarely mean anything. (Randomly replaced "
     "letters)",
     true},
    {"Corrupted Hint",
     "The message seems to be a bit corrupted though and doesn't necessarely mean anything. (Randomly replaced "
     "letters)",
     true},
    {"Corrupted Hint",
     "The message seems to be a bit corrupted though and doesn't necessarely mean anything. (Randomly replaced "
     "letters)",
     true},
    {"Corrupted Hint",
     "The message seems to be a bit corrupted though and doesn't necessarely mean anything. (Randomly replaced "
     "letters)",
     true},
    {"Corrupted Hint",
     "The message seems to be a bit corrupted though and doesn't necessarely mean anything. (Randomly replaced "
     "letters)",
     true},
};
extern "C" char *wrap_text_to_width_alloc(char *, int);
static const auto &wrapped_descriptions() {
  static const auto result = [] {
    std::array<std::string, sizeof(perks) / sizeof(*perks)> descriptions;
    for (size_t i = 0; i < descriptions.size(); ++i) {
      char *wrapped = wrap_text_to_width_alloc(const_cast<char *>(perks[i].description), 25);
      descriptions[i] = wrapped;
      delete[] wrapped;
    }
    return descriptions;
  }();
  return result;
}
const char *perk_name(int i) { return perks[i].name; }
const char *perk_description(int i) { return wrapped_descriptions()[i].c_str(); }
extern "C" {
unsigned char perk_choice_flags[48], freeware_show_secret_hints;
int config_player_count = 1, perk_id_count = 32, perk_id_perk_expert = 25;
freeware_perk_entry_t perk_meta_table[48];
void perks_generate_choices();
}
void Game::open_perks() {
  if (!run.pending || survival)
    return;
  if (run.choices.empty()) {
    config_player_count = players();
    freeware_show_secret_hints = secret_hints;
    for (int i = 0; i <= perk_id_count; ++i) {
      perk_meta_table[i].available = perks[i].coop;
      perk_meta_table[i].secret = i >= 26;
    }
    std::copy(run.perks.begin(), run.perks.end(), player_state_table[0].freeware.perks);
    perks_generate_choices();
    for (int i = 1; i <= perk_id_count; ++i)
      if (perk_choice_flags[i])
        run.choices.push_back(i);
  }
  selected = 0;
  screen = Screen::Perks;
}
void Game::choose_perk(int choice) {
  if (choice < 0 || choice >= int(run.choices.size()))
    return;
  auto *previous = freeware_frame_game;
  freeware_frame_game = this;
  current_player_index = 0;
  freeware_grant_perk(run.choices[choice]);
  freeware_frame_game = previous;
}
} // namespace freeware
