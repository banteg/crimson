/* ###
 * Create the Grim2D config dialog procedure function entry if missing.
 * @category Analysis
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class CreateConfigDialogProc extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x10002120);
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Function function = functionManager.getFunctionAt(addr);
        if (function == null) {
            function = createFunction(addr, "grim_config_dialog_proc");
            if (function != null) {
                println("CreateConfigDialogProc: created function at " + addr);
            } else {
                printerr("CreateConfigDialogProc: failed to create function at " + addr);
            }
        } else {
            println("CreateConfigDialogProc: function already exists at " + addr);
        }
    }
}
