#!/usr/bin/env bash
# Builds YTDiag.dylib — read-only sign-in / App Attest diagnostics for YouTube.
# Objective-C only: clang + the iPhoneOS SDK. No Theos, no Swift, no SPM.

set -euo pipefail
cd "$(dirname "$0")"

MIN_IOS="15.0"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
echo "SDK:  $SDK"
echo "Xcode: $(xcodebuild -version 2>/dev/null | head -1)"

mkdir -p out

echo "compiling YTDiag.dylib ..."
xcrun --sdk iphoneos clang \
    -target "arm64-apple-ios${MIN_IOS}" \
    -isysroot "$SDK" \
    -O2 \
    -fobjc-arc \
    -dynamiclib \
    -fblocks \
    -framework Foundation \
    -framework UIKit \
    -Xlinker -install_name \
    -Xlinker "@rpath/YTDiag.dylib" \
    -o out/YTDiag.dylib \
    Sources/YTDiag.m

size="$(stat -f%z out/YTDiag.dylib)"
echo "  out/YTDiag.dylib  ${size} bytes"

echo "checking the symbols the report depends on ..."
for sym in DCAppAttestService SecTaskCopyValueForEntitlement NSClassFromString; do
    if xcrun nm -u out/YTDiag.dylib | grep -q "$sym"; then
        echo "  ok: $sym"
    else
        echo "  note: $sym not an undefined import (may be resolved via dlsym)"
    fi
done

shasum -a 256 out/YTDiag.dylib
echo
echo "done."
