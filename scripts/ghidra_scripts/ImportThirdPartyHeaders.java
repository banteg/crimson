/* ###
 * Import third-party headers into the current program's data type manager.
 * @category Data Types
 */

import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.program.model.data.DataTypeManager;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ImportThirdPartyHeaders extends GhidraScript {

    @Override
    public void run() throws Exception {
        String headersRoot = null;
        String[] args = getScriptArgs();
        if (args.length > 0 && args[0] != null && !args[0].isBlank()) {
            headersRoot = args[0];
        }
        if (headersRoot == null || headersRoot.isBlank()) {
            headersRoot = System.getenv("CRIMSON_HEADERS_DIR");
        }
        if (headersRoot == null || headersRoot.isBlank()) {
            headersRoot = "source/headers/third_party";
        }

        File root = new File(headersRoot);
        if (!root.exists()) {
            printerr("Headers dir not found: " + root.getAbsolutePath());
            return;
        }

        List<String> headerFiles = new ArrayList<>();
        List<String> missing = new ArrayList<>();

        addHeader(headerFiles, missing, new File(root, "jpeglib.h"));
        addHeader(headerFiles, missing, new File(root, "zlib.h"));
        addHeader(headerFiles, missing, new File(root, "ogg/ogg.h"));
        addHeader(headerFiles, missing, new File(root, "vorbis/codec.h"));
        addHeader(headerFiles, missing, new File(root, "vorbis/vorbisfile.h"));

        if (headerFiles.isEmpty()) {
            printerr("No headers found to parse under: " + root.getAbsolutePath());
            return;
        }

        if (!missing.isEmpty()) {
            println("Skipping missing headers: " + String.join(", ", missing));
        }

        String[] includePaths = new String[] {
            root.getAbsolutePath(),
            new File(root, "ogg").getAbsolutePath(),
            new File(root, "vorbis").getAbsolutePath(),
        };

        String[] cppArgs = new String[] {
            "-D_WIN32",
            "-DWIN32",
            "-DCHAR_BIT=8",
            "-DUCHAR_MAX=255",
            "-DSHRT_MIN=-32768",
            "-DSHRT_MAX=32767",
            "-DUSHRT_MAX=65535",
            "-DINT_MIN=-2147483648",
            "-DINT_MAX=2147483647",
            "-DUINT_MAX=4294967295U",
            "-DLONG_MIN=-2147483648",
            "-DLONG_MAX=2147483647",
            "-DULONG_MAX=4294967295U",
            "-Dva_list=void*",
        };

        DataTypeManager dtMgr = currentProgram.getDataTypeManager();
        println("Parsing third-party headers into: " + dtMgr.getName());
        println("Headers root: " + root.getAbsolutePath());

        boolean hadErrors = false;
        for (String header : headerFiles) {
            try {
                CParseResults results = CParserUtils.parseHeaderFiles(
                    null,
                    new String[] { header },
                    includePaths,
                    cppArgs,
                    dtMgr,
                    monitor
                );
                if (!results.successful()) {
                    printerr("Header parse reported errors: " + header);
                    hadErrors = true;
                }
            }
            catch (Exception e) {
                printerr("Header parse failed: " + header + " (" + e.getMessage() + ")");
                hadErrors = true;
            }
        }

        if (hadErrors) {
            printerr("One or more headers failed to parse. See script log for details.");
        }
    }

    private void addHeader(List<String> headerFiles, List<String> missing, File file) {
        if (file.exists()) {
            headerFiles.add(file.getAbsolutePath());
        }
        else {
            missing.add(file.getPath());
        }
    }
}
