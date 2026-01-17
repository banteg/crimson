// Create functions for Grim2D vtable entries so ExportFunctions can capture them.
// @category Crimsonland

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class CreateGrim2DVtableFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        long vtableAddr = 0x1004c238L;
        int maxEntries = 200;
        int nullRunLimit = 8;

        String[] args = getScriptArgs();
        if (args.length > 0) {
            vtableAddr = parseLong(args[0]);
        }
        if (args.length > 1) {
            maxEntries = (int) parseLong(args[1]);
        }

        int ptrSize = currentProgram.getDefaultPointerSize();
        int created = 0;
        int skipped = 0;
        int nullRun = 0;

        for (int i = 0; i < maxEntries; i++) {
            Address entryAddr = toAddr(vtableAddr + (long) i * ptrSize);
            long funcPtr;
            if (ptrSize == 4) {
                funcPtr = Integer.toUnsignedLong(getInt(entryAddr));
            } else {
                funcPtr = getLong(entryAddr);
            }

            if (funcPtr == 0) {
                nullRun++;
                if (nullRun >= nullRunLimit) {
                    break;
                }
                continue;
            }
            nullRun = 0;

            Address funcAddr = toAddr(funcPtr);
            MemoryBlock block = currentProgram.getMemory().getBlock(funcAddr);
            if (block == null || !block.isExecute()) {
                skipped++;
                continue;
            }

            Function f = getFunctionAt(funcAddr);
            if (f == null) {
                if (disassemble(funcAddr)) {
                    f = createFunction(funcAddr, null);
                } else {
                    f = createFunction(funcAddr, null);
                }
            }

            if (f != null) {
                created++;
            } else {
                skipped++;
            }
        }

        println("CreateGrim2DVtableFunctions: created=" + created + " skipped=" + skipped);
    }
}
