import json

from crimson.dbg.state_digest import session_digest
from crimson.game_modes import GameMode
from crimson.perks.ids import PerkId
from crimson.sim.input import PlayerInput
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from grim.geom import Vec2

rows = {}
for preserve in [False, True]:
    for count in [1, 2]:
        for perk in PerkId:
            session = initialize_run(
                RunSpec(game_mode_id=GameMode.SURVIVAL, seed=123, player_count=count, preserve_bugs=preserve),
            ).session
            for player in session.world.players:
                player.perk_counts[perk] = 1
                player.health = 70.0
                player.weapon.shot_cooldown = 0.0
                player.man_bomb_timer = 5.0
                player.fire_cough_timer = 8.0
                player.hot_tempered_timer = 5.0
            creature = session.world.creatures.entries[0]
            creature.active = True
            creature.hp = 500.0
            creature.max_hp = 500.0
            creature.size = 50.0
            creature.pos = Vec2(530.0, 512.0)
            creature.reward_value = 50.0
            creature.lifecycle_stage = 16.0
            session.world.state.jinxed_timer = -0.1
            inputs = tuple(PlayerInput(aim=Vec2(530.0, 512.0), fire_down=True) for _ in session.world.players)
            trace = []
            for _tick in range(4):
                session.step_tick(dt=0.1, inputs=inputs)
                trace.append(session_digest(session))
            rows[f"{preserve}/{count}/{perk.name}"] = trace
print(json.dumps(rows, sort_keys=True))
