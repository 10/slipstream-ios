#!/var/jb/bin/sh
# Embedded as each Debian maintainer script by scripts/release.py.
set -eu
PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
base=/var/jb
ctl=$base/usr/local/bin/slipstreamctl
case '@SCRIPT@:'"${1:-}" in
 preinst:install|preinst:upgrade)
  if [ -x "$base/usr/local/bin/slipstream" ] && [ "$("$base/usr/local/bin/slipstream" backend 2>/dev/null || true)" != native ]; then
   if [ -f "$base/etc/slipstream/enabled" ]; then
    echo 'Turn protection off in the existing Slipstream version before this one-time native VPN migration, then retry.' >&2
    exit 1
   fi
   # The installed old binary is the authority for its PF, routes, DNS and netagent state.
   /var/jb/bin/sh "$base/usr/local/bin/slipstreamctl" disable
  fi
  ;;
 prerm:remove|prerm:deconfigure)
  # Remove the exact owned native configuration while the helper is still on disk.
  /var/jb/bin/sh "$ctl" disable
  ;;
 postinst:configure|postinst:abort-upgrade|postinst:abort-remove|postinst:abort-deconfigure)
  mkdir -p "$base/etc/slipstream" "$base/var/run/slipstream"
  chown root:wheel "$base/etc/slipstream" "$base/var/run/slipstream"
  chmod 700 "$base/etc/slipstream" "$base/var/run/slipstream"
  chown -R root:wheel "$base/Applications/Slipstream.app"
  chmod 4755 "$base/Applications/Slipstream.app/slipstream-helper"
  # Retire files from package and earlier manual installations.
  rm -f "$base/Library/LaunchDaemons/local.slipstream.plist"
  rm -f "$base/usr/local/bin/slipstream-sockets" "$base/etc/slipstream/direct-domains.json" "$base/etc/slipstream/direct-domains.json.new"
  uicache -p "$base/Applications/Slipstream.app"
  if [ -f "$base/etc/slipstream/enabled" ]; then
   /var/jb/bin/sh "$ctl" enable
  fi
  ;;
 postrm:remove)
  uicache -u "$base/Applications/Slipstream.app" 2>/dev/null || true
  ;;
 postrm:purge)
  for name in config.json proxies.json direct-domains.json app-routing.json enabled control.lock tunnel.uuid; do
   rm -f "$base/etc/slipstream/$name" "$base/etc/slipstream/$name.new"
  done
  rmdir "$base/etc/slipstream" 2>/dev/null || true
  ;;
esac
