/* ###
 * Split the credits secret update function out of the match-3 checker block.
 * @category Analysis
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class CreateCreditsSecretUpdate extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address matchAddr = toAddr(0x0040f400);
        Address secretAddr = toAddr(0x0040f4f0);
        FunctionManager functionManager = currentProgram.getFunctionManager();

        Function containing = functionManager.getFunctionContaining(secretAddr);
        if (containing != null && !containing.getEntryPoint().equals(secretAddr)) {
            println("CreateCreditsSecretUpdate: removing function at " + containing.getEntryPoint());
            removeFunction(containing);
        }

        Function matchFunc = functionManager.getFunctionAt(matchAddr);
        if (matchFunc == null) {
            matchFunc = createFunction(matchAddr, "credits_secret_match3_find");
            if (matchFunc != null) {
                println("CreateCreditsSecretUpdate: created match-3 function at " + matchAddr);
            } else {
                printerr("CreateCreditsSecretUpdate: failed to create match-3 function at " + matchAddr);
            }
        } else {
            println("CreateCreditsSecretUpdate: match-3 function already exists at " + matchAddr);
        }

        Function secretFunc = functionManager.getFunctionAt(secretAddr);
        if (secretFunc == null) {
            secretFunc = createFunction(secretAddr, "credits_secret_alien_zookeeper_update");
            if (secretFunc != null) {
                println("CreateCreditsSecretUpdate: created secret update function at " + secretAddr);
            } else {
                printerr("CreateCreditsSecretUpdate: failed to create secret update function at " + secretAddr);
            }
        } else {
            println("CreateCreditsSecretUpdate: secret update function already exists at " + secretAddr);
        }
    }
}
