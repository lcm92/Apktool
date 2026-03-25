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

import java.util.regex.Pattern;

public class TypeRenamer {

    public static String renameType(String type) {
        if (type == null || type.isEmpty()) return type;
        if (type.charAt(0) == '[') return "[" + renameType(type.substring(1));
        if (type.charAt(0) != 'L' || !type.endsWith(";")) return type;

        String inner = type.substring(1, type.length() - 1);
        String[] pathParts = inner.split("/");

        String[] packages = new String[pathParts.length - 1];
        System.arraycopy(pathParts, 0, packages, 0, packages.length);
        String classAndInner = pathParts[pathParts.length - 1];

        boolean wrapInDef;
        if (packages.length > 0) {
            wrapInDef = false;
        } else {
            String outerClass = classAndInner.split("\\$", -1)[0];
            wrapInDef = isObfuscatedDefaultClass(outerClass);
        }

        StringBuilder result = new StringBuilder("L");
        if (wrapInDef) result.append(RenameRules.getDefPackage()).append("/");

        for (int i = 0; i < packages.length; i++) {
            if (i > 0) result.append("/");
            result.append(renamePackageSegment(packages[i]));
        }
        if (packages.length > 0) result.append("/");

        boolean renameClassNames = packages.length == 0 || !isSystemPackage(packages[0]);

        String[] classParts = classAndInner.split("\\$", -1);
        for (int j = 0; j < classParts.length; j++) {
            if (j > 0) result.append("$");
            String part = classParts[j];
            boolean obfuscated = packages.length == 0
                ? isObfuscatedDefaultClass(part)
                : isObfuscatedClassName(part);
            if (renameClassNames && obfuscated) {
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
        if (pathParts.length > 1 && pathParts[0].equals(RenameRules.getDefPackage())) startIdx = 1;

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

    // ========== Package rename ==========

    static String renamePackageSegment(String seg) {
        if (seg.isEmpty()) return seg;
        if (isObfuscatedPackage(seg) && Character.isUpperCase(seg.charAt(0))) {
            return "_" + seg.toLowerCase();
        }
        return seg;
    }

    static String unrenamePackageSegment(String seg) {
        if (seg.isEmpty()) return seg;
        if (seg.charAt(0) == '_' && seg.length() >= 2) {
            String candidate = Character.toUpperCase(seg.charAt(1)) + seg.substring(2);
            if (RenameRules.getPkgPattern().matcher(candidate).matches()) {
                return candidate;
            }
        }
        return seg;
    }

    // ========== Outer class rename ==========

    static String renameOuterClass(String name, String[] packages) {
        String prefix = (Character.isUpperCase(name.charAt(0))) ? "_" : "";
        return prefix + name.toUpperCase() + getPackageContext(packages);
    }

    static String unrenameOuterClass(String renamed, String[] originalPackages) {
        boolean wasUppercase = renamed.startsWith("_");
        String name = wasUppercase ? renamed.substring(1) : renamed;
        String expectedContext = getPackageContext(originalPackages);
        if (expectedContext.length() > 0 && name.endsWith(expectedContext)) {
            name = name.substring(0, name.length() - expectedContext.length());
        }
        if (name.isEmpty()) return renamed;
        String candidate = wasUppercase
            ? Character.toUpperCase(name.charAt(0)) + name.substring(1)
            : name.toLowerCase();
        Pattern pattern = originalPackages.length == 0
            ? RenameRules.getDefClsPattern()
            : RenameRules.getClsPattern();
        if (pattern.matcher(candidate).matches()) {
            return candidate;
        }
        return renamed;
    }

    // ========== Inner class rename ==========

    static String renameInnerClass(String name, String parentOriginal, int depth) {
        if (parentOriginal.isEmpty()) return name;
        String prefix = (Character.isUpperCase(name.charAt(0))) ? "_" : "";
        char parentChar = Character.toUpperCase(parentOriginal.charAt(0));
        return prefix + name.toUpperCase() + parentChar + depth;
    }

    static String unrenameInnerClass(String renamed, String parentOriginal, int depth) {
        if (parentOriginal.isEmpty()) return renamed;
        boolean wasUppercase = renamed.startsWith("_");
        String name = wasUppercase ? renamed.substring(1) : renamed;
        char expectedParentChar = Character.toUpperCase(parentOriginal.charAt(0));
        String expectedSuffix = "" + expectedParentChar + depth;
        if (name.endsWith(expectedSuffix)) {
            name = name.substring(0, name.length() - expectedSuffix.length());
        }
        if (name.isEmpty()) return renamed;
        String candidate = wasUppercase
            ? Character.toUpperCase(name.charAt(0)) + name.substring(1)
            : name.toLowerCase();
        if (RenameRules.getClsPattern().matcher(candidate).matches()) {
            return candidate;
        }
        return renamed;
    }

    // ========== Context ==========

    static String getPackageContext(String[] packages) {
        StringBuilder ctx = new StringBuilder();
        int count = Math.min(3, packages.length);
        for (int i = 0; i < count; i++) {
            String pkg = packages[packages.length - 1 - i];
            if (isObfuscatedPackage(pkg) && Character.isUpperCase(pkg.charAt(0))) {
                ctx.append("_").append(Character.toUpperCase(pkg.charAt(0)));
            } else {
                ctx.append(Character.toUpperCase(pkg.charAt(0)));
            }
        }
        return ctx.toString();
    }

    // ========== Detection ==========

    static boolean isSystemPackage(String topPackage) {
        return RenameRules.getSystemPackages().contains(topPackage);
    }

    static boolean isObfuscatedPackage(String seg) {
        if (seg.isEmpty()) return false;
        return RenameRules.getPkgPattern().matcher(seg).matches();
    }

    static boolean isObfuscatedClassName(String seg) {
        if (seg.isEmpty()) return false;
        return RenameRules.getClsPattern().matcher(seg).matches();
    }

    static boolean isObfuscatedDefaultClass(String seg) {
        if (seg.isEmpty()) return false;
        return RenameRules.getDefClsPattern().matcher(seg).matches();
    }
}
