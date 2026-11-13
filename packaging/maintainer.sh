#!/var/jb/bin/sh
# Embedded as each Debian maintainer script by scripts/release.py.
set -eu
PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
base=/var/jb
ctl=$base/usr/local/bin/slipstreamctl
case '@SCRIPT@:'"${1:-}" in
 preinst:upgrade)
  if dpkg --compare-versions "${2:-}" lt 0.7.0; then
   echo 'Upgrading from Slipstream before 0.7.0 is not supported. Install 0.7.1 first, or remove the old version.' >&2
   exit 1
  fi
  ;;
 prerm:remove|prerm:deconfigure)
  # Remove the exact owned native configuration while the CLI is still on disk.
  /var/jb/bin/sh "$ctl" disable
  ;;
 postinst:configure|postinst:abort-upgrade|postinst:abort-remove|postinst:abort-deconfigure)
  mkdir -p "$base/etc/slipstream" "$base/var/run/slipstream"
  chown root:wheel "$base/etc/slipstream" "$base/var/run/slipstream"
  chmod 700 "$base/etc/slipstream" "$base/var/run/slipstream"
  chown -R root:wheel "$base/Applications/Slipstream.app"
  chmod 4755 "$base/Applications/Slipstream.app/slipstream-helper"
  # Releases before 0.7.2 copied the selected proxy and its credentials here.
  rm -f "$base/etc/slipstream/config.json" "$base/etc/slipstream/config.json.new"
  uicache -p "$base/Applications/Slipstream.app"
  if [ -f "$base/etc/slipstream/enabled" ]; then
   /var/jb/bin/sh "$ctl" enable
  fi
  ;;
 postrm:remove)
  uicache -u "$base/Applications/Slipstream.app" 2>/dev/null || true
  ;;
 postrm:purge)
  rm -rf "$base/etc/slipstream" "$base/var/run/slipstream"
  ;;
esac
