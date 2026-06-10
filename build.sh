#!/bin/bash
# =============================================================================
# PROCESS DUMPER - Incremental Build Script
# =============================================================================

set -e

# --- Compiler / linker settings ----------------------------------------------
CXX=x86_64-w64-mingw32-g++
CXXFLAGS="-std=c++17 -Wall -O2 -m64"
LDFLAGS="-static-libgcc -static-libstdc++ -lntdll -lpsapi"
OUTPUT="process_dumper.exe"

# --- Source files ------------------------------------------------------------
SOURCES=(
    "PE_Parser/parser.cpp"
    "entry_point.cpp"
)

# --- Build directory ---------------------------------------------------------
OBJ_DIR=".build"
mkdir -p "$OBJ_DIR"

# --- Helpers -----------------------------------------------------------------
needs_rebuild() {
    local src="$1"
    local obj="$2"
    # Rebuild if .o doesn't exist, or .cpp is newer than .o
    [[ ! -f "$obj" ]] || [[ "$src" -nt "$obj" ]]
}

# --- Compile phase -----------------------------------------------------------
OBJECTS=()
REBUILT=0

for src in "${SOURCES[@]}"; do
    # Flatten path to a valid .o filename (e.g. PE_Parser/parser.cpp -> PE_Parser_parser.o)
    obj_name="${src//\//_}"
    obj_name="${obj_name//.cpp/.o}"
    obj="$OBJ_DIR/$obj_name"

    OBJECTS+=("$obj")

    if needs_rebuild "$src" "$obj"; then
        echo "[COMPILE] $src"
        $CXX $CXXFLAGS -c "$src" -o "$obj"
        REBUILT=1
    else
        echo "[  UP-TO-DATE  ] $src"
    fi
done

# --- Link phase --------------------------------------------------------------
# Always relink if any object was freshly compiled, or if the exe is missing
if [[ $REBUILT -eq 1 ]] || [[ ! -f "$OUTPUT" ]]; then
    echo "[LINK] ${OBJECTS[*]} -> $OUTPUT"
    $CXX $CXXFLAGS "${OBJECTS[@]}" -o "$OUTPUT" $LDFLAGS
    echo "[DONE] Build successful: $OUTPUT"
else
    echo "[DONE] Nothing to rebuild."
fi