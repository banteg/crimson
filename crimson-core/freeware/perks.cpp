// Metadata in original registration order (0x407920); the selection flags are per mode.
#include "game.h"
#include <algorithm>
#include <cmath>
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
static const char *const hints[] = {
    "As newly born stay still waiting for a monster to come. Slay it with a single shot and go standing on the "
    "dead body of the monster waiting for its friends to come tear you apart. When at near death condition one "
    "will be given a gift one can keep if still remaining alive.",
    "To get one of them, one has to as said. One has to                                                           "
    "                            weapon.",
    "Beware of the false information. Some may try to lead you astray. Everything doesn't make sense.",
    "Always the same about the Secret Weapon: jymrmpibftxkmnmstqvxz",
    "Mitahan ihmeellista kielta taakin on? Eipa tasta taida mitaan hyotya olla kuitenkaan.. vai?",
    "One left, two right, four forth and six back. And again. What does it form if left is back and Ceasar is not "
    "only an emperor?",
    "Only a true bubble boy survives peacefully over kaksi minuuttia without a scratch."};
const char *perk_name(int i) { return perks[i].name; }
const char *perk_description(int i) { return perks[i].description; }
void Game::open_perks() {
  if (!run.pending || survival)
    return;
  if (run.choices.empty()) {
    // 0x408cf0 rolls distinct eligible choices and displays them in registration order.
    std::vector<int> available;
    for (int i = 1; i <= 32; ++i)
      if ((two_players ? perks[i].coop : (i < 26 || secret_hints)) && !run.perks[i])
        available.push_back(i);
    if (available.empty()) { // Repeat eligible perks once the remaining pool is exhausted.
      for (int i = 1; i <= 32; ++i)
        if ((two_players ? perks[i].coop : (i < 26 || secret_hints)))
          available.push_back(i);
    }
    int count = run.perks[25] ? 7 : 5;
    while (count-- && !available.empty()) {
      int index = crt_rand() % int(available.size());
      run.choices.push_back(available[index]);
      available.erase(available.begin() + index);
    }
    std::sort(run.choices.begin(), run.choices.end());
  }
  selected = 0;
  screen = Screen::Perks;
}
void Game::choose_perk(int choice) {
  if (choice < 0 || choice >= int(run.choices.size()))
    return;
  const int id = run.choices[choice];
  ++run.perks[id];
  switch (id) {
  case 8:
    run.experience += 2500;
    break;
  case 9:
    run.experience += 6666;
    run.health = -1;
    break;
  case 19:
    if (crt_rand() % 2 == 0)
      run.experience += 10000;
    else
      run.health = -1;
    break;
  case 20:
  case 21:
    weapon_assign_player(0, id == 20 ? 2 : 3);
    player_state_table[0].freeware.clip_size += id == 20 ? 10 : 5;
    break;
  case 24:
    run.level += 3;
    run.pending += 3;
    run.health = .1f;
    break;
  }
  for (int i = 0; i < players(); ++i)
    std::copy(run.perks.begin(), run.perks.end(), player_state_table[i].freeware.perks);
  --run.pending;
  run.choices.clear();
  screen = Screen::Playing;
  if (id >= 26 && id <= 32) {
    message = hints[id - 26];
    if (id != 29)
      for (char &c : message)
        if (c != ' ' && crt_rand() % 5 < 2)
          c = char('a' + crt_rand() % 26);
    screen = Screen::Message;
  }
}
} // namespace freeware
