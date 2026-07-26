// Run queued analyzers after repository maps mutate functions, types, and data.
// @category Crimson

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;

public class FinalizeAnalysis extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if ("1".equals(System.getenv("CRIMSON_GHIDRA_FINALIZE_FULL"))) {
            println("Running initial whole-program analysis after repository map application...");
            AutoAnalysisManager manager =
                AutoAnalysisManager.getAnalysisManager(currentProgram);
            manager.reAnalyzeAll(currentProgram.getMemory());
            manager.startAnalysis(monitor, false);
        }
        else {
            println("Finalizing queued analysis after repository map application...");
            analyzeChanges(currentProgram);
        }
        println("Analysis finalization complete.");
    }
}
