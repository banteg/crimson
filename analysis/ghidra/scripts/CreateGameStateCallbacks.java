/* ###
 * Split and create game-state callback functions that Ghidra otherwise merges.
 * @category Analysis
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class CreateGameStateCallbacks extends GhidraScript {
    private static class Seed {
        final long address;
        final String name;

        Seed(long address, String name) {
            this.address = address;
            this.name = name;
        }
    }

    // Order matters: highest entrypoints first so lower-entry functions do not
    // re-absorb the split callback blocks.
    private static final Seed[] SEEDS = new Seed[] {
        new Seed(0x004423d0L, "highscore_screen_update"),
        new Seed(0x00442150L, "ui_update_notice_update"),
        new Seed(0x00440960L, "unlocked_perks_database_update"),
        new Seed(0x00440110L, "unlocked_weapons_database_update"),
        new Seed(0x0043f550L, "statistics_menu_update"),
        new Seed(0x0043efc0L, "ui_list_widget_update"),
        new Seed(0x0040e9a0L, "mods_menu_update"),
        new Seed(0x0040e940L, "mods_any_available"),
    };

    @Override
    public void run() throws Exception {
        FunctionManager functionManager = currentProgram.getFunctionManager();

        int removed = 0;
        int created = 0;
        int skipped = 0;

        for (Seed seed : SEEDS) {
            Address addr = toAddr(seed.address);
            Function containing = functionManager.getFunctionContaining(addr);
            if (containing != null && !containing.getEntryPoint().equals(addr)) {
                println("CreateGameStateCallbacks: removing function at "
                    + containing.getEntryPoint() + " to split " + addr);
                removeFunction(containing);
                removed++;
            }

            Function function = functionManager.getFunctionAt(addr);
            if (function != null) {
                skipped++;
                continue;
            }

            if (currentProgram.getListing().getInstructionAt(addr) == null) {
                disassemble(addr);
            }

            function = createFunction(addr, seed.name);
            if (function != null) {
                println("CreateGameStateCallbacks: created function at " + addr);
                created++;
            } else {
                printerr("CreateGameStateCallbacks: failed to create function at " + addr);
            }
        }

        println("CreateGameStateCallbacks: created=" + created + " removed=" + removed + " skipped=" + skipped);
    }
}
