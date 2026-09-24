#!/bin/sh
# Run as root ON THE PHONE from the extracted build/install directory.
set -eu
PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo 'root required' >&2; exit 1; }
base=/var/jb
[ -x "$base/bin/sh" ] || { echo 'This build does not match the jailbreak layout. Use the rootless or rootful build for this phone.' >&2; exit 1; }
if [ -x "$base/usr/local/bin/slipstream" ] && [ "$("$base/usr/local/bin/slipstream" backend 2>/dev/null || true)" != native ]; then
 if [ -f "$base/etc/slipstream/enabled" ]; then
  echo 'Turn protection off in the existing Slipstream version before this one-time native VPN migration, then retry.' >&2
  exit 1
 fi
 # The installed old binary is the authority for its PF, routes, DNS and netagent state.
 /var/jb/bin/sh "$base/usr/local/bin/slipstreamctl" disable
fi
mkdir -p "$base/usr/local/bin" "$base/etc/slipstream" "$base/var/run/slipstream" "$base/Library/LaunchDaemons"
chmod 700 "$base/etc/slipstream" "$base/var/run/slipstream"
cp slipstream "$base/usr/local/bin/slipstream.new"
chmod 755 "$base/usr/local/bin/slipstream.new"
mv "$base/usr/local/bin/slipstream.new" "$base/usr/local/bin/slipstream"
rm -f "$base/usr/local/bin/slipstream-sockets" "$base/etc/slipstream/direct-domains.json" "$base/etc/slipstream/direct-domains.json.new"
cp slipstreamctl "$base/usr/local/bin/slipstreamctl"
chmod 755 "$base/usr/local/bin/slipstreamctl"
rm -f "$base/Library/LaunchDaemons/local.slipstream.plist"
mkdir -p "$base/Applications/Slipstream.app"
# The app proxy replaced the packet tunnel provider of earlier releases.
rm -rf "$base/Applications/Slipstream.app/PlugIns/PacketProvider.appex"
cp -R Slipstream.app/. "$base/Applications/Slipstream.app/"
chown -R root:wheel "$base/Applications/Slipstream.app"
chmod 755 "$base/Applications/Slipstream.app" "$base/Applications/Slipstream.app/Slipstream"
chmod 4755 "$base/Applications/Slipstream.app/slipstream-helper"
uicache -p "$base/Applications/Slipstream.app"
if [ -f "$base/etc/slipstream/enabled" ]; then
 /var/jb/bin/sh "$base/usr/local/bin/slipstreamctl" enable
fi
echo 'Installed. Open Slipstream from the Home Screen to import and select proxies.'
