/* ###
 * Apply function names/signatures from a CSV mapping.
 * @category Analysis
 */

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.FunctionSignatureParser;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApplyNameMap extends GhidraScript {
    private static class Row {
        String program;
        String address;
        String name;
        String signature;
        String comment;
    }

    private static String defaultMapPath() {
        String localPath = "source" + File.separator + "ghidra" + File.separator + "name_map.csv";
        File localFile = new File(localPath);
        if (localFile.exists()) {
            return localFile.getAbsolutePath();
        }
        return null;
    }

    private static List<String> parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (inQuotes) {
                if (ch == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        current.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    current.append(ch);
                }
            } else {
                if (ch == '"') {
                    inQuotes = true;
                } else if (ch == ',') {
                    fields.add(current.toString().trim());
                    current.setLength(0);
                } else {
                    current.append(ch);
                }
            }
        }
        fields.add(current.toString().trim());
        return fields;
    }

    private static long parseAddress(String address) throws NumberFormatException {
        String value = address.trim();
        if (value.startsWith("0x") || value.startsWith("0X")) {
            value = value.substring(2);
        }
        return Long.parseUnsignedLong(value, 16);
    }

    private static Map<String, Integer> headerIndex(List<String> header) {
        Map<String, Integer> map = new HashMap<>();
        for (int i = 0; i < header.size(); i++) {
            map.put(header.get(i).toLowerCase(), i);
        }
        return map;
    }

    private Row readRow(List<String> fields, Map<String, Integer> headerMap) {
        Row row = new Row();
        row.program = getField(fields, headerMap, "program");
        row.address = getField(fields, headerMap, "address");
        row.name = getField(fields, headerMap, "name");
        row.signature = getField(fields, headerMap, "signature");
        row.comment = getField(fields, headerMap, "comment");
        return row;
    }

    private String getField(List<String> fields, Map<String, Integer> headerMap, String key) {
        Integer idx = headerMap.get(key);
        if (idx == null || idx < 0 || idx >= fields.size()) {
            return "";
        }
        return fields.get(idx).trim();
    }

    @Override
    public void run() throws Exception {
        String mapPath = null;
        String[] args = getScriptArgs();
        if (args.length > 0 && args[0] != null && !args[0].isBlank()) {
            mapPath = args[0];
        }
        if (mapPath == null || mapPath.isBlank()) {
            mapPath = System.getenv("CRIMSON_NAME_MAP");
        }
        if (mapPath == null || mapPath.isBlank()) {
            mapPath = defaultMapPath();
        }
        if (mapPath == null || mapPath.isBlank()) {
            printerr("Name map not found. Set CRIMSON_NAME_MAP or pass a path.");
            return;
        }

        File mapFile = new File(mapPath);
        if (!mapFile.exists()) {
            printerr("Name map not found: " + mapFile.getAbsolutePath());
            return;
        }

        String programName = currentProgram.getName();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionSignatureParser parser = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);

        int applied = 0;
        int renamed = 0;
        int signatures = 0;
        int comments = 0;
        int missing = 0;
        int skipped = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(mapFile))) {
            String line;
            Map<String, Integer> headerMap = null;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                List<String> fields = parseCsvLine(line);
                if (headerMap == null) {
                    headerMap = headerIndex(fields);
                    if (!headerMap.containsKey("address") || !headerMap.containsKey("name")) {
                        printerr("Invalid header in name map: " + line);
                        return;
                    }
                    continue;
                }
                Row row = readRow(fields, headerMap);
                if (row.address == null || row.address.isBlank()) {
                    continue;
                }
                if (row.program != null && !row.program.isBlank()) {
                    if (!row.program.equalsIgnoreCase(programName)) {
                        skipped++;
                        continue;
                    }
                }
                Address addr;
                try {
                    addr = toAddr(parseAddress(row.address));
                } catch (NumberFormatException e) {
                    printerr("Invalid address: " + row.address);
                    continue;
                }
                Function function = functionManager.getFunctionAt(addr);
                if (function == null) {
                    printerr("No function at " + addr + " for " + row.name);
                    missing++;
                    continue;
                }

                boolean changed = false;
                if (row.name != null && !row.name.isBlank()) {
                    try {
                        if (!function.getName().equals(row.name)) {
                            function.setName(row.name, SourceType.USER_DEFINED);
                            renamed++;
                            changed = true;
                        }
                    } catch (DuplicateNameException | InvalidInputException e) {
                        printerr("Rename failed for " + row.name + ": " + e.getMessage());
                    }
                }

                if (row.signature != null && !row.signature.isBlank()) {
                    try {
                        FunctionDefinitionDataType sig = parser.parse(null, row.signature);
                        ApplyFunctionSignatureCmd cmd =
                            new ApplyFunctionSignatureCmd(function.getEntryPoint(), sig, SourceType.USER_DEFINED);
                        if (cmd.applyTo(currentProgram, monitor)) {
                            signatures++;
                            changed = true;
                        } else {
                            printerr("Signature apply failed for " + row.name + ": " + row.signature);
                        }
                    } catch (Exception e) {
                        printerr("Signature parse failed for " + row.name + ": " + e.getMessage());
                    }
                }

                if (row.comment != null && !row.comment.isBlank()) {
                    function.setComment(row.comment);
                    comments++;
                    changed = true;
                }

                if (changed) {
                    applied++;
                }
            }
        } catch (IOException e) {
            printerr("Failed to read name map: " + e.getMessage());
            return;
        }

        println("Applied name map: " + mapFile.getAbsolutePath());
        println("Program: " + programName);
        println("Updated entries: " + applied);
        println("Renamed: " + renamed + ", Signatures: " + signatures + ", Comments: " + comments);
        println("Missing: " + missing + ", Skipped: " + skipped);
    }
}
