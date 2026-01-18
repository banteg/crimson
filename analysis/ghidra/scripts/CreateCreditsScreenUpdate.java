/* ###
 * Create the credits screen update function entry if missing.
 * @category Analysis
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class CreateCreditsScreenUpdate extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x0040d800);
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Function function = functionManager.getFunctionAt(addr);
        if (function == null) {
            function = createFunction(addr, "credits_screen_update");
            if (function != null) {
                println("CreateCreditsScreenUpdate: created function at " + addr);
            } else {
                printerr("CreateCreditsScreenUpdate: failed to create function at " + addr);
            }
        } else {
            println("CreateCreditsScreenUpdate: function already exists at " + addr);
        }
    }
}
