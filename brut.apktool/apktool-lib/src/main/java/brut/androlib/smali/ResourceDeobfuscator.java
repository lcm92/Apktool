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

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.ZipDexContainer;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Field;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
import com.android.tools.smali.dexlib2.iface.value.IntEncodedValue;

import java.io.*;
import java.util.*;

/**
 * Collects original resource names directly from R$ classes in dex files
 * using dexlib2 API. No smali decode needed.
 */
public class ResourceDeobfuscator {

    /**
     * Scan all dex files in APK for R$ resource ID fields.
     * Returns map: "0x7fXXYYYY" -> "originalFieldName"
     */
    public static Map<String, String> collectLostResourceNames(File apkFile) throws IOException {
        Map<String, String> map = new HashMap<>();

        ZipDexContainer container = new ZipDexContainer(apkFile, null);
        try {
            container.getEntry(""); // eager init
        } catch (IOException ignored) {
            return map;
        }

        for (String dexName : container.getDexEntryNames()) {
            try {
                ZipDexContainer.DexEntry<DexBackedDexFile> entry = container.getEntry(dexName);
                if (entry == null) continue;
                DexBackedDexFile dexFile = entry.getDexFile();
                collectFromDex(dexFile, map);
            } catch (Exception ignored) {
            }
        }

        return map;
    }

    private static void collectFromDex(DexBackedDexFile dexFile, Map<String, String> map) {
        for (ClassDef classDef : dexFile.getClasses()) {
            String className = classDef.getType(); // e.g. "Lcom/example/R$drawable;"

            // Only process R$ inner classes
            if (!className.contains("/R$") && !className.contains("$R$")) {
                continue;
            }

            boolean isStyleClass = className.endsWith("$style;") || className.endsWith("$styleable;");

            for (Field field : classDef.getStaticFields()) {
                // Only int fields (resource IDs)
                if (!field.getType().equals("I")) continue;

                EncodedValue initValue = field.getInitialValue();
                if (initValue == null) continue;
                if (!(initValue instanceof IntEncodedValue)) continue;

                int value = ((IntEncodedValue) initValue).getValue();
                // Only app resources (0x7f prefix)
                if ((value & 0xFF000000) != 0x7F000000) continue;

                String fieldName = field.getName();
                if (isStyleClass) {
                    fieldName = fieldName.replace("_", ".");
                }

                String hexId = String.format("0x%08x", value);
                map.put(hexId, fieldName);
            }
        }
    }
}
