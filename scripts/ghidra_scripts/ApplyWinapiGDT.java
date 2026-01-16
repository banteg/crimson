/* ###
 * Apply WinAPI .gdt function signatures to the current program.
 * @category Data Types
 */

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.symbol.SourceType;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ApplyWinapiGDT extends GhidraScript {

    @Override
    public void run() throws Exception {
        String gdtPath = null;
        String[] args = getScriptArgs();
        if (args.length > 0 && args[0] != null && !args[0].isBlank()) {
            gdtPath = args[0];
        }
        if (gdtPath == null || gdtPath.isBlank()) {
            gdtPath = System.getenv("CRIMSON_WINAPI_GDT");
        }
        if (gdtPath == null || gdtPath.isBlank()) {
            String localPath = "source" + File.separator + "ghidra" + File.separator + "winapi_32.gdt";
            File localFile = new File(localPath);
            if (localFile.exists()) {
                gdtPath = localFile.getAbsolutePath();
            } else {
                gdtPath = "/Users/banteg/dev/0x6d696368/ghidra-data/typeinfo/winapi_32.gdt";
            }
        }

        File gdtFile = new File(gdtPath);
        if (!gdtFile.exists()) {
            printerr("GDT not found: " + gdtFile.getAbsolutePath());
            return;
        }

        println("Applying WinAPI GDT: " + gdtFile.getAbsolutePath());

        FileDataTypeManager archive = null;
        try {
            archive = FileDataTypeManager.openFileArchive(gdtFile, false);
            List<DataTypeManager> managers = new ArrayList<>();
            managers.add(archive);
            managers.add(currentProgram.getDataTypeManager());

            ApplyFunctionDataTypesCmd cmd =
                new ApplyFunctionDataTypesCmd(managers, null, SourceType.USER_DEFINED, true, false);
            if (!cmd.applyTo(currentProgram, monitor)) {
                printerr("ApplyFunctionDataTypesCmd failed.");
            }
        }
        catch (Exception e) {
            printerr("Failed to apply GDT: " + e.getMessage());
        }
        finally {
            if (archive != null) {
                archive.close();
            }
        }
    }
}
