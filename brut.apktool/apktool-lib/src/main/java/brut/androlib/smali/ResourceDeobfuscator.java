/*
 *  Copyright (C) 2010 Ryszard Wiśniewski <brut.alll@gmail.com>
 *  Copyright (C) 2010 Connor Tumbleson <connor.tumbleson@gmail.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package brut.androlib.smali;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Collects original resource names from R$*.smali files.
 * These files contain static final fields mapping field names to resource hex IDs:
 *   .field public static final ic_launcher:I = 0x7f080001
 * This allows recovering original resource names that were obfuscated in resources.arsc.
 */
public class ResourceDeobfuscator {

    /**
     * Scan all smali files for R$ resource ID fields.
     * Returns map: "0x7fXXYYYY" -> "originalFieldName"
     */
    public static Map<String, String> collectLostResourceNames(File outDir) throws IOException {
        Map<String, String> map = new HashMap<>();

        Path base = outDir.toPath();
        if (!Files.exists(base)) return map;

        Files.walk(base)
            .filter(Files::isRegularFile)
            .filter(path -> {
                String s = path.toString();
                return (s.contains("smali") || s.contains("smali_")) && s.endsWith(".smali");
            })
            .forEach(path -> {
                try {
                    collectFromSmali(path, map);
                } catch (IOException ignored) {
                }
            });

        return map;
    }

    private static void collectFromSmali(Path path, Map<String, String> map) throws IOException {
        boolean isStyleClass = path.toString().contains("$style");

        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            boolean inStaticFields = false;

            while ((line = br.readLine()) != null) {
                if (line.startsWith("# static fields")) {
                    inStaticFields = true;
                    continue;
                }
                if (line.startsWith("# direct methods") || line.startsWith("# virtual methods")) {
                    inStaticFields = false;
                    continue;
                }

                if (!inStaticFields) continue;
                if (!line.startsWith(".field public static final ")) continue;
                if (!line.contains(":I = ")) continue;

                // .field public static final fieldName:I = 0x7fXXYYYY
                String cleaned = line.substring(".field public static final ".length());

                // For R$style, field names use _ instead of . for style parent refs
                if (isStyleClass) {
                    cleaned = cleaned.replace("_", ".");
                }

                String[] parts = cleaned.split(":I = ");
                if (parts.length == 2 && parts[1].startsWith("0x7f")) {
                    map.put(parts[1].trim(), parts[0].trim());
                }
            }
        }
    }
}
