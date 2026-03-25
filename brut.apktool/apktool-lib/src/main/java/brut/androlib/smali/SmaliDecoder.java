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

import brut.androlib.exceptions.AndrolibException;
import brut.util.OS;
import com.android.tools.smali.baksmali.Baksmali;
import com.android.tools.smali.baksmali.BaksmaliOptions;
import com.android.tools.smali.dexlib2.analysis.InlineMethodResolver;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedOdexFile;
import com.android.tools.smali.dexlib2.dexbacked.ZipDexContainer;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.rewriter.DexRewriter;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliDecoder {
    private final ZipDexContainer mDexContainer;
    private final boolean mDebugMode;
    private final Set<String> mDexFiles;
    private final AtomicInteger mInferredApiLevel;

    public SmaliDecoder(File apkFile, boolean debugMode) throws AndrolibException {
        mDexContainer = new ZipDexContainer(apkFile, null);
        // ZipDexContainer is lazily initialized and not thread-safe. Eagerly initialize on the constructing thread.
        try {
            mDexContainer.getEntry("");
        } catch (IOException ex) {
            throw new AndrolibException("Could not open apk file: " + apkFile, ex);
        }
        mDebugMode = debugMode;
        mDexFiles = ConcurrentHashMap.newKeySet();
        mInferredApiLevel = new AtomicInteger();
    }

    public Set<String> getDexFiles() {
        return mDexFiles;
    }

    public int getInferredApiLevel() {
        return mInferredApiLevel.get();
    }

    public void decode(String dexName, File outDir) throws AndrolibException {
        try {
            // Fetch the requested dex file from the dex container.
            ZipDexContainer.DexEntry<DexBackedDexFile> dexEntry = mDexContainer.getEntry(dexName);
            if (dexEntry == null) {
                throw new AndrolibException("Could not find file: " + dexName);
            }

            // Add the requested dex file.
            Map<Integer, DexBackedDexFile> dexFiles = new TreeMap<>();
            dexFiles.put(1, dexEntry.getDexFile());

            // Add additional dex files if it's a multi-dex container.
            for (String dexEntryName : mDexContainer.getDexEntryNames()) {
                if (dexEntryName.equals(dexName)) {
                    continue;
                }

                String prefix = dexName + "/";
                if (!dexEntryName.startsWith(prefix)) {
                    continue;
                }

                int dexNum;
                try {
                    dexNum = Integer.parseInt(dexEntryName.substring(prefix.length()));
                } catch (NumberFormatException ignored) {
                    continue;
                }
                if (dexNum > 1) {
                    dexFiles.put(dexNum, mDexContainer.getEntry(dexEntryName).getDexFile());
                }
            }

            // Decode the dex files into separate folders.
            for (Map.Entry<Integer, DexBackedDexFile> entry : dexFiles.entrySet()) {
                int dexNum = entry.getKey();
                DexBackedDexFile dexFile = entry.getValue();

                if (dexFile.supportsOptimizedOpcodes()) {
                    throw new AndrolibException("Cannot disassemble an odex file without deodexing it: " + dexName);
                }

                String dirName = "smali";
                if (dexNum > 1 || !dexName.equals("classes.dex")) {
                    dirName += "_" + dexName.substring(0, dexName.lastIndexOf('.')).replace('/', '@');
                    if (dexNum > 1) {
                        dirName += dexNum;
                    }
                }

                decodeFile(dexFile, new File(outDir, dirName));
            }

            mDexFiles.add(dexName);
        } catch (IOException ex) {
            throw new AndrolibException("Could not baksmali file: " + dexName, ex);
        }
    }

    private void decodeFile(DexBackedDexFile dexFile, File smaliDir) {
        int jobs = Math.min(Runtime.getRuntime().availableProcessors(), 6);

        BaksmaliOptions options = new BaksmaliOptions();
        options.parameterRegisters = true;
        options.localsDirective = true;
        options.sequentialLabels = true;
        options.debugInfo = mDebugMode;
        options.codeOffsets = false;
        options.accessorComments = false;
        options.allowOdex = false;
        options.deodex = false;
        options.implicitReferences = false;
        options.normalizeVirtualMethods = false;
        options.registerInfo = 0;

        if (dexFile instanceof DexBackedOdexFile) {
            options.inlineResolver = InlineMethodResolver.createInlineMethodResolver(
                ((DexBackedOdexFile) dexFile).getOdexVersion());
        }

        // Rename obfuscated types to avoid case-insensitive filesystem collisions
        DexRewriter rewriter = new DexRewriter(new ObfuscatedTypeRewriterModule());
        DexFile rewrittenDex = rewriter.getDexFileRewriter().rewrite(dexFile);

        OS.mkdir(smaliDir);
        Baksmali.disassembleDexFile(rewrittenDex, smaliDir, jobs, options);

        // Fix InnerClass annotation names to match renamed class names
        try {
            fixInnerClassAnnotations(smaliDir);
        } catch (IOException ignored) {
        }

        // Fix Signature annotations - type references in generic signatures are stored
        // as plain strings and not rewritten by DexRewriter's TypeRewriter
        try {
            fixSignatureAnnotations(smaliDir);
        } catch (IOException ignored) {
        }

        // Fix Kotlin Metadata d2 annotations - type references stored as plain strings
        try {
            fixKotlinMetadataAnnotations(smaliDir);
        } catch (IOException ignored) {
        }

        int apiLevel = dexFile.getOpcodes().api;
        mInferredApiLevel.updateAndGet(cur -> (cur == 0 || cur > apiLevel) ? apiLevel : cur);
    }

    private static final Pattern CLASS_PATTERN = Pattern.compile("^\\.class\\s+.*\\s+(L[^;]+;)", Pattern.MULTILINE);

    private static void fixInnerClassAnnotations(File dir) throws IOException {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (file.isDirectory()) {
                fixInnerClassAnnotations(file);
            } else if (file.getName().endsWith(".smali") && file.getName().contains("$")) {
                fixInnerClassAnnotation(file);
            }
        }
    }

    // ========== Signature annotation fix ==========

    private static final Pattern SIG_TYPE_PATTERN = Pattern.compile("L[a-zA-Z][a-zA-Z0-9_/$]*[a-zA-Z0-9_]");

    private static void fixSignatureAnnotations(File dir) throws IOException {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (file.isDirectory()) {
                fixSignatureAnnotations(file);
            } else if (file.getName().endsWith(".smali")) {
                fixSignatureAnnotation(file);
            }
        }
    }

    private static void fixSignatureAnnotation(File smaliFile) throws IOException {
        List<String> lines = Files.readAllLines(smaliFile.toPath(), StandardCharsets.UTF_8);

        boolean inSignature = false;
        boolean modified = false;

        for (int i = 0; i < lines.size(); i++) {
            String trimmed = lines.get(i).trim();
            if (trimmed.equals(".annotation system Ldalvik/annotation/Signature;")) {
                inSignature = true;
            } else if (trimmed.equals(".end annotation") && inSignature) {
                inSignature = false;
            } else if (inSignature && trimmed.startsWith("\"")) {
                // Process string values in the Signature annotation
                String line = lines.get(i);
                String newLine = renameTypesInSignatureLine(line);
                if (!newLine.equals(line)) {
                    lines.set(i, newLine);
                    modified = true;
                }
            }
        }

        if (modified) {
            Files.write(smaliFile.toPath(), lines, StandardCharsets.UTF_8);
        }
    }

    private static String renameTypesInSignatureLine(String line) {
        // Find type references like Lpackage/Class in the line and rename them
        Matcher m = SIG_TYPE_PATTERN.matcher(line);
        StringBuilder sb = new StringBuilder();
        int lastEnd = 0;
        while (m.find()) {
            String typeRef = m.group(); // e.g. "Lnl/f" or "Lnl/g"
            // Build a full type descriptor to pass to renameType
            // The ';' might be later in the string or in the next fragment
            String fullType = typeRef + ";";
            String renamed = TypeRenamer.renameType(fullType);
            // Strip the trailing ';' since it's not part of our match
            String renamedRef = renamed.substring(0, renamed.length() - 1);

            sb.append(line, lastEnd, m.start());
            sb.append(renamedRef);
            lastEnd = m.end();
        }
        if (lastEnd == 0) return line;
        sb.append(line, lastEnd, line.length());
        return sb.toString();
    }

    // ========== Kotlin Metadata annotation fix ==========

    private static void fixKotlinMetadataAnnotations(File dir) throws IOException {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (file.isDirectory()) {
                fixKotlinMetadataAnnotations(file);
            } else if (file.getName().endsWith(".smali")) {
                fixKotlinMetadataAnnotation(file);
            }
        }
    }

    private static void fixKotlinMetadataAnnotation(File smaliFile) throws IOException {
        List<String> lines = Files.readAllLines(smaliFile.toPath(), StandardCharsets.UTF_8);

        boolean inKotlinMetadata = false;
        boolean inD2 = false;
        boolean modified = false;

        for (int i = 0; i < lines.size(); i++) {
            String trimmed = lines.get(i).trim();
            if (trimmed.equals(".annotation runtime Lkotlin/Metadata;")) {
                inKotlinMetadata = true;
            } else if (trimmed.equals(".end annotation") && inKotlinMetadata) {
                inKotlinMetadata = false;
                inD2 = false;
            } else if (inKotlinMetadata && trimmed.equals("d2 = {")) {
                inD2 = true;
            } else if (inD2 && trimmed.equals("}")) {
                inD2 = false;
            } else if (inD2 && trimmed.startsWith("\"")) {
                String line = lines.get(i);
                String newLine = renameTypesInSignatureLine(line);
                if (!newLine.equals(line)) {
                    lines.set(i, newLine);
                    modified = true;
                }
            }
        }

        if (modified) {
            Files.write(smaliFile.toPath(), lines, StandardCharsets.UTF_8);
        }
    }

    // ========== InnerClass annotation fix ==========

    private static void fixInnerClassAnnotation(File smaliFile) throws IOException {
        List<String> lines = Files.readAllLines(smaliFile.toPath(), StandardCharsets.UTF_8);

        String simpleName = null;
        for (String line : lines) {
            if (line.startsWith(".class ")) {
                Matcher m = CLASS_PATTERN.matcher(line);
                if (m.find()) {
                    String desc = m.group(1);
                    String inner = desc.substring(1, desc.length() - 1);
                    int lastDollar = inner.lastIndexOf('$');
                    if (lastDollar >= 0) {
                        simpleName = inner.substring(lastDollar + 1);
                    }
                }
                break;
            }
        }
        if (simpleName == null) return;

        boolean inInnerClassAnnotation = false;
        boolean modified = false;

        for (int i = 0; i < lines.size(); i++) {
            String trimmed = lines.get(i).trim();
            if (trimmed.equals(".annotation system Ldalvik/annotation/InnerClass;")) {
                inInnerClassAnnotation = true;
            } else if (trimmed.equals(".end annotation") && inInnerClassAnnotation) {
                inInnerClassAnnotation = false;
            } else if (inInnerClassAnnotation && trimmed.startsWith("name = \"")) {
                String newLine = "    name = \"" + simpleName + "\"";
                if (!lines.get(i).equals(newLine)) {
                    lines.set(i, newLine);
                    modified = true;
                }
            }
        }

        if (modified) {
            Files.write(smaliFile.toPath(), lines, StandardCharsets.UTF_8);
        }
    }
}
