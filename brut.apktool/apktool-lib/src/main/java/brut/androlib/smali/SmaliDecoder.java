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
import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.debug.DebugItem;
import com.android.tools.smali.dexlib2.iface.debug.LineNumber;
import com.android.tools.smali.dexlib2.rewriter.DexRewriter;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
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

        // If the dex carries R8-obfuscated line numbers (same line number reused
        // across multiple methods of a class), drop debug info entirely - keeping
        // it would make stack traces point at meaningless lines.
        boolean keepDebugInfo = mDebugMode && !hasObfuscatedDebugLines(dexFile);

        BaksmaliOptions options = new BaksmaliOptions();
        options.parameterRegisters = true;
        options.localsDirective = true;
        options.sequentialLabels = true;
        options.debugInfo = keepDebugInfo;
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

        // Rename obfuscated types to avoid case-insensitive filesystem collisions.
        // Skip classes that declare native methods: JNI binds the native impl to the
        // exact class FQN (auto-binding via Java_<pkg>_<class>_<method> or explicit
        // FindClass/RegisterNatives in C/C++). Renaming breaks that lookup at runtime.
        Set<String> nativeOwners = collectNativeMethodOwners(dexFile);
        DexRewriter rewriter = new DexRewriter(new ObfuscatedTypeRewriterModule(nativeOwners));
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

        // Fix dotted class-FQN string literals (e.g. Hilt's @StringKey/LazyClassKey
        // in HiltViewModelKeys map). DexRewriter's TypeRewriter only touches L...; type
        // descriptors; strings like "g9.e" or "open.chat.x.a" inside const-string ops
        // remain as the original obfuscated FQN and won't match Class.getName() of
        // renamed classes at runtime.
        try {
            Map<String, String> fqnRenameMap = buildFqnRenameMap(dexFile);
            if (!fqnRenameMap.isEmpty()) {
                fixClassNameStringLiterals(smaliDir, fqnRenameMap);
            }
        } catch (IOException ignored) {
        }

        // Fix Hilt @LazyClassKey holder classes whose static String field is decoded
        // at runtime from an obfuscated payload (the payload still encodes the
        // original obfuscated FQN, not the renamed one). Replace <clinit> with a
        // literal sput of the renamed FQN.
        try {
            fixHiltLazyMapKeyClinits(smaliDir);
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

    // ========== Obfuscated debug-line detection ==========

    /**
     * Returns true if any class in the dex has the same source line number
     * appearing in more than one of its methods. In real Java/Kotlin source,
     * methods in a class occupy disjoint line ranges, so a duplicated line
     * across methods is a strong signal that R8 (or another obfuscator) has
     * remapped LineNumberTable entries to non-source-faithful values. Stack
     * traces emitted with such numbers are misleading; the caller can then
     * disable {@code BaksmaliOptions.debugInfo} so debug info is dropped at
     * decode time instead.
     */
    private static boolean hasObfuscatedDebugLines(DexBackedDexFile dexFile) {
        for (ClassDef cls : dexFile.getClasses()) {
            Set<Integer> seen = new HashSet<>();
            for (Method m : cls.getMethods()) {
                MethodImplementation impl = m.getImplementation();
                if (impl == null) continue;
                Set<Integer> methodLines = new HashSet<>();
                for (DebugItem di : impl.getDebugItems()) {
                    if (di instanceof LineNumber) {
                        methodLines.add(((LineNumber) di).getLineNumber());
                    }
                }
                for (Integer line : methodLines) {
                    if (!seen.add(line)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // ========== Native-method class detection ==========

    /**
     * Returns the set of class types whose definition contains at least one
     * method with the {@code native} access flag. These class FQNs are bound to
     * a corresponding C/C++ symbol or used in {@code FindClass}/{@code RegisterNatives}
     * calls, so renaming them breaks runtime native binding.
     */
    private static Set<String> collectNativeMethodOwners(DexBackedDexFile dexFile) {
        Set<String> result = new HashSet<>();
        int nativeFlag = AccessFlags.NATIVE.getValue();
        for (ClassDef cls : dexFile.getClasses()) {
            for (Method m : cls.getMethods()) {
                if ((m.getAccessFlags() & nativeFlag) != 0) {
                    result.add(cls.getType());
                    break;
                }
            }
        }
        return result;
    }

    // ========== Class FQN string-literal fix ==========

    /**
     * Build a map of original dotted FQN -> renamed dotted FQN by applying TypeRenamer
     * to every class type in the DEX. Only entries that were actually renamed are kept.
     */
    private static Map<String, String> buildFqnRenameMap(DexBackedDexFile dexFile) {
        Map<String, String> map = new HashMap<>();
        for (ClassDef cls : dexFile.getClasses()) {
            String origType = cls.getType();
            String renamedType = TypeRenamer.renameType(origType);
            if (origType.equals(renamedType)) continue;
            if (origType.length() < 3 || renamedType.length() < 3) continue;
            String origFqn = origType.substring(1, origType.length() - 1).replace('/', '.');
            String renamedFqn = renamedType.substring(1, renamedType.length() - 1).replace('/', '.');
            map.put(origFqn, renamedFqn);
        }
        return map;
    }

    // Matches a quoted dotted identifier of the shape used by class FQN strings.
    private static final Pattern QUOTED_FQN_PATTERN = Pattern.compile(
        "\"([a-zA-Z_$][a-zA-Z0-9_$]*(?:\\.[a-zA-Z_$][a-zA-Z0-9_$]*)+)\""
    );

    private static void fixClassNameStringLiterals(File dir, Map<String, String> fqnMap) throws IOException {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (file.isDirectory()) {
                fixClassNameStringLiterals(file, fqnMap);
            } else if (file.getName().endsWith(".smali")) {
                fixClassNameStringLiteralsInFile(file, fqnMap);
            }
        }
    }

    private static void fixClassNameStringLiteralsInFile(File smaliFile, Map<String, String> fqnMap) throws IOException {
        List<String> lines = Files.readAllLines(smaliFile.toPath(), StandardCharsets.UTF_8);
        boolean modified = false;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String trimmed = line.trim();
            // Skip metadata lines that already use unrenamed FQN forms intentionally.
            if (trimmed.startsWith(".source") || trimmed.startsWith(".class")
                || trimmed.startsWith(".super") || trimmed.startsWith(".implements")) {
                continue;
            }
            Matcher m = QUOTED_FQN_PATTERN.matcher(line);
            StringBuilder sb = new StringBuilder();
            int lastEnd = 0;
            boolean changed = false;
            while (m.find()) {
                String inner = m.group(1);
                String renamed = fqnMap.get(inner);
                if (renamed != null) {
                    sb.append(line, lastEnd, m.start());
                    sb.append('"').append(renamed).append('"');
                    lastEnd = m.end();
                    changed = true;
                }
            }
            if (changed) {
                sb.append(line, lastEnd, line.length());
                lines.set(i, sb.toString());
                modified = true;
            }
        }
        if (modified) {
            Files.write(smaliFile.toPath(), lines, StandardCharsets.UTF_8);
        }
    }

    // ========== Hilt @LazyClassKey clinit fix ==========

    private static final Pattern LAZY_MAP_KEY_SOURCE = Pattern.compile(
        "\\.source\\s+\"(.+?)_HiltModules_(?:BindsModule_Binds|KeyModule_Provide)_LazyMapKey\\.java\""
    );

    private static final Pattern CLASS_DECL_PATTERN = Pattern.compile(
        "^\\.class[^L]*L([^;]+);"
    );

    private static void fixHiltLazyMapKeyClinits(File dir) throws IOException {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (file.isDirectory()) {
                fixHiltLazyMapKeyClinits(file);
            } else if (file.getName().endsWith(".smali")) {
                fixHiltLazyMapKeyClinitInFile(file);
            }
        }
    }

    private static void fixHiltLazyMapKeyClinitInFile(File smaliFile) throws IOException {
        List<String> lines = Files.readAllLines(smaliFile.toPath(), StandardCharsets.UTF_8);

        String targetSimpleName = null;
        String thisClassPath = null;
        for (String line : lines) {
            String t = line.trim();
            if (targetSimpleName == null) {
                Matcher m = LAZY_MAP_KEY_SOURCE.matcher(t);
                if (m.matches()) {
                    targetSimpleName = m.group(1);
                }
            }
            if (thisClassPath == null) {
                Matcher m = CLASS_DECL_PATTERN.matcher(line);
                if (m.find()) {
                    thisClassPath = m.group(1);
                }
            }
            if (targetSimpleName != null && thisClassPath != null) break;
        }
        if (targetSimpleName == null || thisClassPath == null) return;

        String renamedFqn = findSiblingClassRenamedFqn(smaliFile.getParentFile(), targetSimpleName);
        if (renamedFqn == null) return;

        // Locate <clinit> method and the field it sets
        int clinitStart = -1, clinitEnd = -1;
        for (int i = 0; i < lines.size(); i++) {
            String t = lines.get(i).trim();
            if (clinitStart == -1 && t.startsWith(".method") && t.endsWith("<clinit>()V")) {
                clinitStart = i;
            } else if (clinitStart != -1 && t.equals(".end method")) {
                clinitEnd = i;
                break;
            }
        }
        if (clinitStart == -1 || clinitEnd == -1) return;

        String quotedClass = Pattern.quote(thisClassPath);
        Pattern sputPattern = Pattern.compile(
            "sput-object\\s+v\\d+,\\s+L" + quotedClass + ";->(\\w+):Ljava/lang/String;"
        );
        String fieldName = null;
        for (int i = clinitStart; i <= clinitEnd; i++) {
            Matcher m = sputPattern.matcher(lines.get(i));
            if (m.find()) {
                fieldName = m.group(1);
                break;
            }
        }
        if (fieldName == null) return;

        List<String> rewritten = new ArrayList<>(lines.subList(0, clinitStart));
        rewritten.add(lines.get(clinitStart));
        rewritten.add("    .locals 1");
        rewritten.add("");
        rewritten.add("    const-string v0, \"" + renamedFqn + "\"");
        rewritten.add("");
        rewritten.add("    sput-object v0, L" + thisClassPath + ";->" + fieldName + ":Ljava/lang/String;");
        rewritten.add("");
        rewritten.add("    return-void");
        rewritten.add(".end method");
        rewritten.addAll(lines.subList(clinitEnd + 1, lines.size()));

        Files.write(smaliFile.toPath(), rewritten, StandardCharsets.UTF_8);
    }

    /**
     * Search siblings of {@code parentDir} for a smali whose .source matches
     * "{simpleName}.kt" or "{simpleName}.java" but is NOT itself a Hilt-generated
     * helper class. Returns the renamed dotted FQN of the first match, or null.
     */
    private static String findSiblingClassRenamedFqn(File parentDir, String simpleName) throws IOException {
        if (parentDir == null) return null;
        File[] siblings = parentDir.listFiles();
        if (siblings == null) return null;
        Pattern sourcePattern = Pattern.compile(
            "\\.source\\s+\"" + Pattern.quote(simpleName) + "\\.(?:kt|java)\""
        );
        for (File sib : siblings) {
            if (sib.isDirectory() || !sib.getName().endsWith(".smali")) continue;
            List<String> lines = Files.readAllLines(sib.toPath(), StandardCharsets.UTF_8);
            String classPath = null;
            boolean sourceMatch = false;
            for (String line : lines) {
                String t = line.trim();
                if (!sourceMatch && sourcePattern.matcher(t).matches()) {
                    sourceMatch = true;
                }
                if (classPath == null) {
                    Matcher m = CLASS_DECL_PATTERN.matcher(line);
                    if (m.find()) classPath = m.group(1);
                }
                if (sourceMatch && classPath != null) {
                    return classPath.replace('/', '.');
                }
            }
        }
        return null;
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
