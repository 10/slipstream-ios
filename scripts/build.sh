#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
root=$PWD
. scripts/scheme.sh
rm -rf build/install
mkdir -p vendor build/install
revision=fc77ca3182b3a63b84266bb0a5d24c096e022765
if [ ! -d vendor/tun2proxy/.git ]; then
 gh repo clone tun2proxy/tun2proxy vendor/tun2proxy -- --quiet
 git -C vendor/tun2proxy checkout --quiet "$revision"
fi
[ "$(git -C vendor/tun2proxy rev-parse HEAD)" = "$revision" ] || { echo 'Unexpected revision: vendor/tun2proxy' >&2; exit 1; }
if ! git -C vendor/tun2proxy apply --reverse --check "$root/patches/tun2proxy-ios.patch" 2>/dev/null; then
 git -C vendor/tun2proxy apply "$root/patches/tun2proxy-ios.patch"
fi
rustup target add aarch64-apple-ios
export IPHONEOS_DEPLOYMENT_TARGET=14.0
cargo build --locked --release --target aarch64-apple-ios
cp target/aarch64-apple-ios/release/slipstream build/install/
ldid -Ilocal.slipstream.app -Spackaging/cli-entitlements.plist build/install/slipstream
sed "s#/var/jb#$SLIPSTREAM_PREFIX#g" scripts/slipstreamctl > build/install/slipstreamctl
./scripts/build-app.sh
chmod 755 build/install/slipstream build/install/slipstreamctl
printf 'Built %s/build/install (%s)\n' "$root" "$SLIPSTREAM_SCHEME"
