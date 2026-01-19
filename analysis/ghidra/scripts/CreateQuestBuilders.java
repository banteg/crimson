/* ###
 * Create quest builder functions at entrypoint addresses from name_map.json.
 * @category Analysis
 */

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CreateQuestBuilders extends GhidraScript {
    private static class Row {
        String program;
        String address;
        String name;
    }

    private static String defaultMapPath() {
        String jsonPath = "analysis" + File.separator + "ghidra" + File.separator + "maps"
            + File.separator + "name_map.json";
        File jsonFile = new File(jsonPath);
        if (jsonFile.exists()) {
            return jsonFile.getAbsolutePath();
        }
        return null;
    }

    private static long parseAddressValue(String address) throws NumberFormatException {
        String value = address.trim();
        int radix = 10;
        if (value.startsWith("0x") || value.startsWith("0X")) {
            value = value.substring(2);
            radix = 16;
        } else if (value.matches(".*[a-fA-F].*")) {
            radix = 16;
        }
        return Long.parseUnsignedLong(value, radix);
    }

    private List<Row> readJsonRows(File mapFile) throws IOException {
        List<Row> rows = new ArrayList<>();
        Gson gson = new Gson();
        try (BufferedReader reader = new BufferedReader(new FileReader(mapFile))) {
            JsonElement root = JsonParser.parseReader(reader);
            if (root == null || root.isJsonNull()) {
                return rows;
            }
            if (root.isJsonArray()) {
                JsonArray array = root.getAsJsonArray();
                for (JsonElement element : array) {
                    Row row = gson.fromJson(element, Row.class);
                    if (row != null) {
                        rows.add(row);
                    }
                }
            } else if (root.isJsonObject()) {
                JsonObject obj = root.getAsJsonObject();
                if (obj.has("entries") && obj.get("entries").isJsonArray()) {
                    JsonArray array = obj.get("entries").getAsJsonArray();
                    for (JsonElement element : array) {
                        Row row = gson.fromJson(element, Row.class);
                        if (row != null) {
                            rows.add(row);
                        }
                    }
                } else if (obj.has("address")) {
                    Row row = gson.fromJson(obj, Row.class);
                    if (row != null) {
                        rows.add(row);
                    }
                }
            }
        }
        return rows;
    }

    @Override
    public void run() throws Exception {
        String mapPath = defaultMapPath();
        if (mapPath == null || mapPath.isBlank()) {
            printerr("CreateQuestBuilders: name map not found.");
            return;
        }

        File mapFile = new File(mapPath);
        if (!mapFile.exists()) {
            printerr("CreateQuestBuilders: name map not found: " + mapFile.getAbsolutePath());
            return;
        }

        List<Row> rows;
        try {
            rows = readJsonRows(mapFile);
        } catch (IOException e) {
            printerr("CreateQuestBuilders: failed to read name map: " + e.getMessage());
            return;
        }

        if (rows.isEmpty()) {
            printerr("CreateQuestBuilders: name map is empty.");
            return;
        }

        String programName = currentProgram.getName();
        FunctionManager functionManager = currentProgram.getFunctionManager();

        int created = 0;
        int skipped = 0;

        for (Row row : rows) {
            if (row == null || row.address == null || row.address.isBlank()) {
                continue;
            }
            if (row.program != null && !row.program.isBlank()) {
                if (!row.program.equalsIgnoreCase(programName)) {
                    continue;
                }
            }
            if (row.name == null || row.name.isBlank() || !row.name.startsWith("quest_build_")) {
                continue;
            }

            Address addr;
            try {
                addr = toAddr(parseAddressValue(row.address));
            } catch (NumberFormatException e) {
                printerr("CreateQuestBuilders: invalid address " + row.address + " for " + row.name);
                continue;
            }

            Function function = functionManager.getFunctionAt(addr);
            if (function != null) {
                skipped++;
                continue;
            }

            function = createFunction(addr, row.name);
            if (function != null) {
                function.setName(row.name, SourceType.USER_DEFINED);
                created++;
            } else {
                printerr("CreateQuestBuilders: failed to create function at " + addr + " for " + row.name);
            }
        }

        println("CreateQuestBuilders: created " + created + ", skipped " + skipped);
    }
}
