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

import com.android.tools.smali.dexlib2.rewriter.Rewriter;
import com.android.tools.smali.dexlib2.rewriter.RewriterModule;
import com.android.tools.smali.dexlib2.rewriter.Rewriters;

import java.util.Collections;
import java.util.Set;

public class ObfuscatedTypeRewriterModule extends RewriterModule {
    private final Set<String> mPreservedTypes;

    public ObfuscatedTypeRewriterModule() {
        this(Collections.emptySet());
    }

    public ObfuscatedTypeRewriterModule(Set<String> preservedTypes) {
        mPreservedTypes = preservedTypes != null ? preservedTypes : Collections.emptySet();
    }

    @Override
    public Rewriter<String> getTypeRewriter(Rewriters rewriters) {
        return value -> {
            // Preserve types whose backing class has native methods (or whose
            // outer class does). JNI binds native impls to the exact FQN, both
            // for auto-binding (Java_<pkg>_<class>_<method>) and for explicit
            // FindClass/RegisterNatives calls in C/C++. Renaming such a class
            // makes the lookup fail at runtime.
            if (!mPreservedTypes.isEmpty() && value != null
                && value.length() > 1 && value.charAt(0) == 'L' && value.endsWith(";")) {
                if (mPreservedTypes.contains(value)) {
                    return value;
                }
                // Preserve inner classes of a native-bearing outer class too,
                // since C++ reflection often walks from the outer class.
                int dollar = value.indexOf('$');
                if (dollar > 0) {
                    String outer = value.substring(0, dollar) + ";";
                    if (mPreservedTypes.contains(outer)) {
                        return value;
                    }
                }
            }
            return TypeRenamer.renameType(value);
        };
    }
}
