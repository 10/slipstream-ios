# Sourced by the build scripts. Rootless jailbreaks install under /var/jb; rootful ones (every
# iOS 14 jailbreak) use /.
case ${SLIPSTREAM_SCHEME:=rootless} in
 rootless) SLIPSTREAM_PREFIX=/var/jb ;;
 rootful) SLIPSTREAM_PREFIX= ;;
 *) echo 'SLIPSTREAM_SCHEME must be rootless or rootful' >&2; exit 2 ;;
esac
export SLIPSTREAM_SCHEME SLIPSTREAM_PREFIX
