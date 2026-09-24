#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
root=$PWD
# Rootless jailbreaks install under /var/jb; rootful ones (every iOS 14 jailbreak) use /.
case ${SLIPSTREAM_SCHEME:=rootless} in
 rootless) SLIPSTREAM_PREFIX=/var/jb ;;
 rootful) SLIPSTREAM_PREFIX= ;;
 *) echo 'SLIPSTREAM_SCHEME must be rootless or rootful' >&2; exit 2 ;;
esac
export SLIPSTREAM_SCHEME SLIPSTREAM_PREFIX
mkdir -p vendor build/install
# Remove the retired helper from incremental build archives.
rm -f build/install/slipstream-sockets build/install/local.slipstream.plist
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
for script in slipstreamctl install.sh; do sed "s#/var/jb#$SLIPSTREAM_PREFIX#g" "scripts/$script" > "build/install/$script"; done
cp THIRD_PARTY.md build/install/
./scripts/build-app.sh
chmod 755 build/install/slipstream build/install/slipstreamctl build/install/install.sh
archive=slipstream-ios-arm64.tar
[ "$SLIPSTREAM_SCHEME" = rootless ] || archive=slipstream-ios-arm64-rootful.tar
(cd build && COPYFILE_DISABLE=1 tar --no-xattrs -cf "$archive" install)
printf 'Built %s/build/%s\n' "$root" "$archive"
