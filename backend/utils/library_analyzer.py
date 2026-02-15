"""
Library Analyzer — detects common Android libraries used in the APK.
Helps identify outdated or potentially vulnerable components.
"""
import os
import re

# Common library package signatures
LIB_SIGNATURES = {
    "Retrofit": r"com/squareup/retrofit2",
    "OkHttp": r"com/squareup/okhttp3",
    "Gson": r"com/google/gson",
    "Jackson": r"com/fasterxml/jackson",
    "Glide": r"com/bumptech/glide",
    "Picasso": r"com/squareup/picasso",
    "Firebase": r"com/google/firebase",
    "Google Play Services": r"com/google/android/gms",
    "Realm": r"io/realm",
    "SQLite (SQLCipher)": r"net/sqlcipher",
    "Dagger/Hilt": r"dagger/hilt",
    "RxJava": r"io/reactivex",
    "Kotlin Coroutines": r"kotlinx/coroutines",
    "Apache Commons": r"org/apache/commons",
}

def analyze_libraries(source_dirs: list) -> list:
    """Identify libraries based on path patterns in decompiled source."""
    detected = set()
    
    for s_dir in source_dirs:
        if not os.path.exists(s_dir):
            continue
            
        for root, dirs, files in os.walk(s_dir):
            # Only check directory structure for speed
            rel_path = os.path.relpath(root, s_dir).replace("\\", "/")
            
            for lib_name, sig in LIB_SIGNATURES.items():
                if sig in rel_path:
                    detected.add(lib_name)
                    
    return sorted(list(detected))
