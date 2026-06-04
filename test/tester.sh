#!/usr/bin/env bash
#
# Docker-based tester for Libc.py.
#
# Idea: Docker is only used as a *source of real libc binaries*. For each image
# we pull the runtime libc.so.6 out of the container (this is the stripped libc a
# challenge would ship), then run Libc.py to fetch the matching linker and unstrip
# the libc, and finally assert that debugging symbols were actually recovered.
#
# Usage:
#   ./test/tester.sh                          # run the default Ubuntu + Debian matrix
#   ./test/tester.sh ubuntu:22.04 debian:12   # test specific images only
#
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBC_PY="$SCRIPT_DIR/../Libc.py"

# Default matrix: a spread of glibc versions across both supported distros.
IMAGES=(
    "ubuntu:18.04"   # glibc 2.27
    "ubuntu:20.04"   # glibc 2.31
    "ubuntu:22.04"   # glibc 2.35
    "ubuntu:24.04"   # glibc 2.39
    "debian:10"      # glibc 2.28
    "debian:11"      # glibc 2.31
    "debian:12"      # glibc 2.36
)
if [ "$#" -gt 0 ]; then
    IMAGES=("$@")
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "err: docker is not available (install it / start the daemon)"
    exit 1
fi

pass=0
fail=0
failed_images=()

for image in "${IMAGES[@]}"; do
    echo "=================================================="
    echo "[*] Testing $image"

    work="$(mktemp -d)"
    libc="$work/libc.so.6"

    # Pull the (symlink-resolved) runtime libc out of the container. `cat` follows
    # the symlink so we get the real ELF, mirroring a stripped challenge libc.
    docker run --rm "$image" sh -c \
        'cat /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null || cat /usr/lib/x86_64-linux-gnu/libc.so.6 2>/dev/null' \
        > "$libc" 2>/dev/null

    if [ ! -s "$libc" ]; then
        echo "[-] FAIL: could not extract libc from $image"
        fail=$((fail + 1)); failed_images+=("$image"); rm -rf "$work"; continue
    fi
    echo "[*] banner: $(strings "$libc" | grep -m1 'GLIBC 2')"

    # Run the tool inside the work dir: -ld gets the linker, -u unstrips the libc.
    ( cd "$work" && python3 "$LIBC_PY" "$libc" -ld -u ) >"$work/run.log" 2>&1
    rc=$?

    ok=1
    # 1. The libc must now carry symbols. main_arena is the canonical heap symbol
    #    that only exists once symbols/debug info have been merged back in.
    if ! nm "$libc" 2>/dev/null | grep -qE ' main_arena$'; then
        echo "[-] libc.so.6 has no 'main_arena' symbol after unstrip"; ok=0
    fi
    # 2. The linker must have been produced and must be unstripped.
    ld="$work/ld-linux-x86-64.so.2"
    if [ ! -s "$ld" ]; then
        echo "[-] linker file was not produced"; ok=0
    elif ! file "$ld" | grep -q 'not stripped'; then
        echo "[-] linker is still stripped"; ok=0
    fi

    if [ "$ok" -eq 1 ]; then
        echo "[+] PASS: $image"
        pass=$((pass + 1))
    else
        echo "[-] FAIL: $image (Libc.py exit=$rc)"
        echo "    --- Libc.py output (tail) ---"
        tail -n 15 "$work/run.log" | sed 's/^/    /'
        fail=$((fail + 1)); failed_images+=("$image")
    fi
    rm -rf "$work"
done

echo "=================================================="
echo "[*] Result: $pass passed, $fail failed"
if [ "$fail" -ne 0 ]; then
    echo "[*] failed: ${failed_images[*]}"
    exit 1
fi
