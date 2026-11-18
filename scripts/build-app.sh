#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
platform=${1:-iphoneos}
. scripts/scheme.sh
export IPHONEOS_DEPLOYMENT_TARGET=14.0
case "$platform" in
 iphoneos) target=arm64-apple-ios14.0; output=build/install/Slipstream.app ;;
 iphonesimulator) target=arm64-apple-ios14.0-simulator; output=build/simulator/Slipstream.app ;;
 *) echo 'usage: build-app.sh [iphoneos|iphonesimulator]' >&2; exit 2 ;;
esac
sdk=$(xcrun --sdk "$platform" --show-sdk-path)
rm -rf "$output"
mkdir -p "$output"
xcrun --sdk "$platform" clang -target "$target" -isysroot "$sdk" -Os -Wall -Wextra -Werror -DSLIPSTREAM_PREFIX=\"$SLIPSTREAM_PREFIX\" -c app/Bridge.c -o "build/Bridge-$platform.o"
xcrun --sdk "$platform" swiftc -target "$target" -sdk "$sdk" -swift-version 5 -O -parse-as-library \
 -import-objc-header app/Bridge.h app/Slipstream.swift "build/Bridge-$platform.o" \
 -Xlinker -rpath -Xlinker @executable_path/Frameworks -framework SwiftUI -framework UIKit -o "$output/Slipstream"
version=${SLIPSTREAM_VERSION:-$(cat VERSION)}
printf '%s' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || { echo 'Use a version such as 0.3.0' >&2; exit 1; }
cp app/Info.plist "$output/Info.plist"
for key in CFBundleShortVersionString CFBundleVersion; do plutil -replace "$key" -string "$version" "$output/Info.plist"; done
cp app/Assets/*.png "$output/"
if [ "$platform" = iphoneos ]; then
 xcrun --sdk iphoneos clang -target "$target" -isysroot "$sdk" -Os -Wall -Wextra -Werror -DSLIPSTREAM_PREFIX=\"$SLIPSTREAM_PREFIX\" app/Helper.c -o "$output/slipstream-helper"
 extension="$output/PlugIns/AppProxyProvider.appex"
 mkdir -p "$extension"
 cp provider/Info.plist "$extension/Info.plist"
 for key in CFBundleShortVersionString CFBundleVersion; do plutil -replace "$key" -string "$version" "$extension/Info.plist"; done
 cargo build --locked --release --target aarch64-apple-ios --lib
 xcrun --sdk iphoneos clang -target "$target" -isysroot "$sdk" -Os -Wall -Wextra -Werror -fobjc-arc -fblocks \
  -fapplication-extension -Wl,-e,_NSExtensionMain provider/AppProxyProvider.m target/aarch64-apple-ios/release/libslipstream.a \
  -framework Foundation -framework Network -framework NetworkExtension -framework SystemConfiguration -framework Security -framework CoreFoundation -liconv -lresolv \
  -o "$extension/AppProxyProvider"
 ldid -Ilocal.slipstream.app.proxy -Sprovider/entitlements.plist "$extension/AppProxyProvider"
 # iOS 14 lacks the Swift concurrency runtime. Newer systems load theirs from /usr/lib/swift first.
 # Xcode's copy carries 7 MB of embedded bitcode, which nothing on the phone reads.
 mkdir -p "$output/Frameworks"
 xcrun bitcode_strip -r "$(dirname "$(xcrun --find swiftc)")/../lib/swift-5.5/iphoneos/libswift_Concurrency.dylib" -o "$output/Frameworks/libswift_Concurrency.dylib"
 ldid -S "$output/Frameworks/libswift_Concurrency.dylib"
 ldid -Ilocal.slipstream.app -Sapp/entitlements.plist "$output/Slipstream"
 ldid -Ilocal.slipstream.app -Spackaging/cli-entitlements.plist "$output/slipstream-helper"
else
 codesign --force --sign - "$output"
fi
printf 'Built %s\n' "$output"
