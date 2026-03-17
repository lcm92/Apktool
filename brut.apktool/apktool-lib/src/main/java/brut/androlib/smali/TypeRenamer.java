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

public class TypeRenamer {

    private static final String DEF_PACKAGE = "def";

    public static String renameType(String type) {
        if (type == null || type.isEmpty()) return type;
        if (type.charAt(0) == '[') return "[" + renameType(type.substring(1));
        if (type.charAt(0) != 'L' || !type.endsWith(";")) return type;

        String inner = type.substring(1, type.length() - 1);
        String[] pathParts = inner.split("/");

        String[] packages = new String[pathParts.length - 1];
        System.arraycopy(pathParts, 0, packages, 0, packages.length);
        String classAndInner = pathParts[pathParts.length - 1];

        // Decide def/ wrapping: packages use 1-2 char rule, root classes use 1-3 char rule
        boolean wrapInDef;
        if (packages.length > 0) {
            wrapInDef = isObfuscatedPackage(packages[0]);
        } else {
            String outerClass = classAndInner.split("\\$", -1)[0];
            wrapInDef = isObfuscatedClassName(outerClass);
        }

        StringBuilder result = new StringBuilder("L");
        if (wrapInDef) result.append(DEF_PACKAGE).append("/");

        for (int i = 0; i < packages.length; i++) {
            if (i > 0) result.append("/");
            result.append(renamePackageSegment(packages[i]));
        }
        if (packages.length > 0) result.append("/");

        String[] classParts = classAndInner.split("\\$", -1);
        for (int j = 0; j < classParts.length; j++) {
            if (j > 0) result.append("$");
            String part = classParts[j];
            if (isObfuscatedClassName(part)) {
                if (j == 0) {
                    result.append(renameOuterClass(part, packages));
                } else {
                    result.append(renameInnerClass(part, classParts[j - 1], j));
                }
            } else {
                result.append(part);
            }
        }
        result.append(";");
        return result.toString();
    }

    public static String unrenameType(String type) {
        if (type == null || type.isEmpty()) return type;
        if (type.charAt(0) == '[') return "[" + unrenameType(type.substring(1));
        if (type.charAt(0) != 'L' || !type.endsWith(";")) return type;

        String inner = type.substring(1, type.length() - 1);
        String[] pathParts = inner.split("/");

        int startIdx = 0;
        if (pathParts.length > 1 && pathParts[0].equals(DEF_PACKAGE)) startIdx = 1;

        int pkgCount = pathParts.length - 1 - startIdx;
        String[] originalPackages = new String[pkgCount];
        for (int i = 0; i < pkgCount; i++) {
            originalPackages[i] = unrenamePackageSegment(pathParts[startIdx + i]);
        }

        StringBuilder result = new StringBuilder("L");
        for (int i = 0; i < originalPackages.length; i++) {
            if (i > 0) result.append("/");
            result.append(originalPackages[i]);
        }
        if (originalPackages.length > 0) result.append("/");

        String classAndInner = pathParts[pathParts.length - 1];
        String[] classParts = classAndInner.split("\\$", -1);
        String[] originalClassParts = new String[classParts.length];

        for (int j = 0; j < classParts.length; j++) {
            if (j > 0) result.append("$");
            if (j == 0) {
                originalClassParts[j] = unrenameOuterClass(classParts[j], originalPackages);
            } else {
                originalClassParts[j] = unrenameInnerClass(classParts[j], originalClassParts[j - 1], j);
            }
            result.append(originalClassParts[j]);
        }
        result.append(";");
        return result.toString();
    }

    // ========== Package rename (1-2 chars) ==========

    static String renamePackageSegment(String seg) {
        if (seg.isEmpty()) return seg;
        if (isObfuscatedUppercasePackage(seg)) return "_" + seg.toLowerCase();
        return seg;
    }

    static String unrenamePackageSegment(String seg) {
        if (seg.isEmpty()) return seg;
        if (seg.charAt(0) == '_' && seg.length() >= 2 && seg.length() <= 3) {
            String rest = seg.substring(1);
            if (rest.length() >= 1 && rest.length() <= 2 && Character.isLowerCase(rest.charAt(0))) {
                return Character.toUpperCase(rest.charAt(0)) + rest.substring(1);
            }
        }
        return seg;
    }

    // ========== Outer class rename (1-3 chars) ==========

    static String renameOuterClass(String name, String[] packages) {
        String prefix = isObfuscatedUppercaseClassName(name) ? "_" : "";
        return prefix + name.toUpperCase() + getPackageContext(packages);
    }

    static String unrenameOuterClass(String renamed, String[] originalPackages) {
        boolean wasUppercase = renamed.startsWith("_");
        String name = wasUppercase ? renamed.substring(1) : renamed;
        String expectedContext = getPackageContext(originalPackages);
        if (expectedContext.length() > 0 && name.endsWith(expectedContext)) {
            name = name.substring(0, name.length() - expectedContext.length());
        }
        if (name.length() >= 1 && name.length() <= 3) {
            if (wasUppercase) return Character.toUpperCase(name.charAt(0)) + name.substring(1);
            else return name.toLowerCase();
        }
        return renamed;
    }

    // ========== Inner class rename (1-3 chars) ==========

    static String renameInnerClass(String name, String parentOriginal, int depth) {
        String prefix = isObfuscatedUppercaseClassName(name) ? "_" : "";
        char parentChar = Character.toUpperCase(parentOriginal.charAt(0));
        return prefix + name.toUpperCase() + parentChar + depth;
    }

    static String unrenameInnerClass(String renamed, String parentOriginal, int depth) {
        boolean wasUppercase = renamed.startsWith("_");
        String name = wasUppercase ? renamed.substring(1) : renamed;
        char expectedParentChar = Character.toUpperCase(parentOriginal.charAt(0));
        String expectedSuffix = "" + expectedParentChar + depth;
        if (name.endsWith(expectedSuffix)) {
            name = name.substring(0, name.length() - expectedSuffix.length());
        }
        if (name.length() >= 1 && name.length() <= 3) {
            if (wasUppercase) return Character.toUpperCase(name.charAt(0)) + name.substring(1);
            else return name.toLowerCase();
        }
        return renamed;
    }

    // ========== Context ==========

    static String getPackageContext(String[] packages) {
        StringBuilder ctx = new StringBuilder();
        int count = Math.min(3, packages.length);
        for (int i = 0; i < count; i++) {
            String pkg = packages[packages.length - 1 - i];
            if (isObfuscatedUppercasePackage(pkg)) {
                ctx.append("_").append(Character.toUpperCase(pkg.charAt(0)));
            } else {
                ctx.append(Character.toUpperCase(pkg.charAt(0)));
            }
        }
        return ctx.toString();
    }

    // ========== Detection helpers ==========

    /** Package obfuscation: 1-3 chars starting with letter or underscore (avoids com, org, net) */
    static boolean isObfuscatedPackage(String seg) {
        if (seg.isEmpty()) return false;
        char first = seg.charAt(0);
        if (first == '_') return seg.length() >= 2 && seg.length() <= 3;
        return seg.length() >= 1 && seg.length() <= 2 && Character.isLetter(first);
    }

    /** Package uppercase: 1-2 chars starting with uppercase */
    static boolean isObfuscatedUppercasePackage(String seg) {
        return seg.length() >= 1 && seg.length() <= 2 && Character.isUpperCase(seg.charAt(0));
    }

    /** Class name obfuscation: 1-3 chars starting with letter or underscore */
    static boolean isObfuscatedClassName(String seg) {
        if (seg.isEmpty()) return false;
        char first = seg.charAt(0);
        if (first == '_') return seg.length() >= 2 && seg.length() <= 4;
        return seg.length() >= 1 && seg.length() <= 3 && Character.isLetter(first);
    }

    /** Class name uppercase: 1-3 chars starting with uppercase */
    static boolean isObfuscatedUppercaseClassName(String seg) {
        return seg.length() >= 1 && seg.length() <= 3 && Character.isUpperCase(seg.charAt(0));
    }
}
