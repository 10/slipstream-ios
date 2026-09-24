# Repeating device checks

Run on the development Mac:

```sh
cargo test --lib
python3 -m unittest discover -s tests -p 'test_*.py'
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -Os tests/probe.c -o build/probe
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -fblocks -Os -framework Network tests/network-framework.c -o build/network-framework
xcrun --sdk iphoneos clang -target arm64-apple-ios14.0 -fblocks -Os -framework CoreFoundation -framework CFNetwork -framework Network tests/interfaces.c -o build/interfaces
ldid -S build/probe
ldid -S build/network-framework
ldid -S build/interfaces
```

## App proxy checks

Protection must add no tunnel interface. On the phone, run `./interfaces > before.json` with protection off and `./interfaces > during.json` once `slipstreamctl status` reports `protected`, in each routing mode. Then, on the Mac:

```sh
python3 tests/audit_interfaces.py before.json during.json
```

It fails when protection adds a `utun`, `tun`, `tap`, `ppp` or `ipsec` name to the scoped proxy settings, the interface list or the default path. iOS's own `utun` interfaces present beforehand are expected. `test_app_proxy.py` checks, without a device, that the audit fails on an added tunnel interface.

Protected apps produce no packets of their own: iOS diverts their flows to the provider, which alone connects to the proxy. Audit a PKTAP capture with the selected app's process name, the provider and every proxy endpoint in use:

```sh
python3 tests/audit_per_app_capture.py capture.pcap --process TikTok --provider AppProxyProvider --proxy PROXY_IP:PORT
```

Any packet attributed to the selected app fails, as does provider traffic to any other endpoint. With a SOCKS5 proxy, UDP to the proxy host is allowed. Also capture an unselected run of the same app, which must fail, to show that attribution works. On the XS, create the capture interface with `ifconfig pktap0 create`, capture with `tcpdump -n -i pktap0 -y PKTAP -s 256 -U -w FILE`, and destroy the interface afterwards.

The Ethernet audit below was written for the device-wide packet tunnel of earlier releases. All apps mode no longer covers system daemons, so their direct traffic is expected there.

Transfer probes through the established SSH connection and make them executable. On the phone, start an Ethernet capture on the actual physical interface (`en0` on the tested XS), then run these probes from their installation directory:

```sh
tcpdump -i en0 -n -s 0 -w /private/var/tmp/slipstream-test.pcap &
capture_pid=$!
curl -fsS --max-time 15 https://api.ipify.org
./probe dns 8.8.8.8 53
./probe udp 1.1.1.1 443 en0
./probe tcp 2606:4700:4700::1111 443
./network-framework tcp 1.1.1.1 80
./network-framework tcp 1.1.1.1 80 wifi
./network-framework udp 1.1.1.1 443 wifi
# Launch TikTok normally and load several new videos during this capture.
kill -INT "$capture_pid"
```

Copy the capture privately to the Mac. Use the phone's current physical MAC address and a private copy of its configuration:

```sh
python3 tests/audit_capture.py /private/path/test.pcap --mac PHONE_MAC --config /private/path/config.json
```

In native All apps mode, add `--local-subnet` for each actual connected LAN subnet; this explicitly models the local-network exclusion. Do not allow all private-address ranges or silently discard unexpected traffic.

Expected: public IP matches the proxy; TikTok plays; ordinary Network.framework TCP receives data; unsupported UDP and physically bound flows cannot escape. IPv6 may work or fail depending on the proxy, but must never go direct. The audit should have real traffic and no violations. Do not treat an empty capture as evidence. Check tcpdump's dropped-packet count and use the actual interface/MAC after each network change.

Failure tests require captures with clear protected intervals:

1. Kill only the verified installed provider PID and trigger fresh requests. Confirm reconnection and require no direct packets from the protected app during recovery. Record initial failures separately from successful recovery.
2. Temporarily use an unreachable proxy endpoint. Both DNS-based and literal-IP Internet requests must fail. Restore the exact private settings and reconnect; never count the deliberate protection-off cleanup interval as protected.
3. Capture continuous traffic during explicit restart, proxy changes, and All apps ↔ Selected apps changes. The overlap of protected app scopes must remain routed or blocked. A proxy switch may use either explicitly recorded proxy endpoint during transition.
4. Explicit disable must remove the owned native profile and restore normal networking. The backend must not install PF rules, change `enable_netagent`, or leave a Slipstream launchd job.
5. Close the app and check that the native session remains Connected. Verify a fresh, nonmultiplexed SSH connection through your jump host while Connected and the phone's Tailscale is off.

For existing-flow activation, start the Network.framework TCP/UDP probes while disabled, enable protection, then audit new and ongoing traffic separately. Do not infer coverage of existing sockets from a new-connection test.

Selected-app checks require a selected ordinary client, an unselected control, DNS, BSD TCP and URLSession/Network.framework. Use a PKTAP capture and `audit_per_app_capture.py` as described under app proxy checks. Safari must be labeled **Not supported** and rejected before saving an unsupported selection.

Before routing/path changes, install a bounded device-side rollback. Keep the current settings private, record exact owned profile/process IDs, and verify new LAN SSH sessions rather than relying on an existing connection. Phone-level Tailscale coexistence is not a requirement.

See [wifi-cycle.md](wifi-cycle.md) for the bounded MobileWiFi helper and its independent restoration watchdog. No active cellular service was available during the recorded validation, so a cellular handoff still requires a provisioned test device.

Raw captures and configurations contain secrets. Store them outside source control and do not paste their payloads into logs.

## SOCKS5 relay checks

Run a relay on a Mac that shares the phone's LAN, then import it as a SOCKS5 list, select it, and enable protection:

```sh
python3 tests/socks5_relay.py --bind LAN_IP --port 1080 --user u --password p
```

Repeat the HTTPS, `probe dns`, and TikTok checks. Then send UDP through the tunnel without an interface argument, for example `./probe stun stun.l.google.com 19302` after resolving the address, and confirm the relay logs `UDP ASSOCIATE` and the probe receives a reply. Rerun the relay with `--no-udp`: Test connection must report *not relayed by this proxy* and the same UDP probe must time out. Audit the capture with the SOCKS5 configuration; `proxy UDP` is expected and any UDP to another Internet host is a violation.

## App checks

Build both `./scripts/build-app.sh` and `./scripts/build-app.sh iphonesimulator`. Simulator fixtures cover empty, off, and protected layouts; only the physical phone verifies privilege and routing behavior. Check light/dark appearance and accessibility text sizes, including a complete exit IP.

On-device, launch from SpringBoard; import invalid input and require a visible line-number error; import a valid list twice and confirm deduplication without a selection change. Exercise search, list filtering, selection, protection off/on, and a connectivity check. Confirm selected-proxy deletion is rejected while enabled, and the helper denies a direct call from another mobile process. Close the app and verify the native session stays protected.

Capture on the physical interface during proxy changes. A transition may legitimately use either the previous or new exact proxy endpoint; audit both explicitly, keeping all other exceptions unchanged. Exclude deliberate protection-off intervals from protected-traffic claims. Check a failed proxy while enabled, then recover by selecting a working proxy.

Latency checks: the authenticated helper requests the handshake from the connected provider in both routing modes. On-device, tap **Test connection** and compare its millisecond value with SYN→SYN/ACK timing in the physical-interface capture. A wrong selection ID must fail, and an unreachable selected proxy must yield no value after the three-second TCP timeout. Check that retesting/selection changes clear stale values, that the HTTPS exit-IP check remains independent, and that the UI stays static between tests. No temporary routing exceptions are needed.

## Packaging and migration

Build and check `python3 scripts/release.py package 0.5.0` and `python3 tests/check_package.py build/io.github.10.slipstream_0.5.0_iphoneos-arm64.deb`. After `SLIPSTREAM_SCHEME=rootful ./scripts/build.sh`, the same commands produce and check `…_iphoneos-arm.deb`. Check the extension identifier/version/executable mode and the unchanged fixed-purpose helper boundary. No legacy routing daemon or socket helper should ship.

The one-time 0.4.x migration requires protection to be off. An enabled old installation must be rejected; its installed binary must clean up its own networking before replacement. Test a disabled legacy upgrade, preserved saved-file hashes, native upgrade/reconnect, and uninstall/reinstall.
