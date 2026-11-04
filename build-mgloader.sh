#!/usr/bin/env bash
# Builds MGLoader.dylib - Option A guest loader skeleton for YouTube.
# Objective-C only: clang + the iPhoneOS SDK. No Theos, no Swift, no SPM.
#
# Round 1 target: injection proof + one instrumented dlopen() of the converted Twitch guest.
# Nothing is loaded automatically, so a bad guest can never take the host down at launch.

set -euo pipefail
cd "$(dirname "$0")"

MIN_IOS="15.0"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
echo "SDK:  $SDK"
echo "Xcode: $(xcodebuild -version 2>/dev/null | head -1)"

mkdir -p out

echo "compiling MGLoader.dylib ..."
xcrun --sdk iphoneos clang \
    -target "arm64-apple-ios${MIN_IOS}" \
    -isysroot "$SDK" \
    -O2 \
    -fobjc-arc \
    -dynamiclib \
    -fblocks \
    -framework Foundation \
    -framework UIKit \
    -framework Security \
    -Xlinker -install_name \
    -Xlinker "@rpath/MGLoader.dylib" \
    -o out/MGLoader.dylib \
    Sources/MGLoader.m

size="$(stat -f%z out/MGLoader.dylib)"
echo "  out/MGLoader.dylib  ${size} bytes"

echo "checking the symbols the loader depends on ..."
for sym in _dlopen _dlerror _dlsym _SecTaskCreateFromSelf; do
    if xcrun nm -u out/MGLoader.dylib | grep -q "$sym"; then
        echo "  ok: $sym"
    else
        echo "  MISSING: $sym"
        exit 1
    fi
done

echo "checking load commands ..."
xcrun otool -l out/MGLoader.dylib | grep -A2 LC_ID_DYLIB || true
xcrun otool -L out/MGLoader.dylib

shasum -a 256 out/MGLoader.dylib
echo
echo "done."
