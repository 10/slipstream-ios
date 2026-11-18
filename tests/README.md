# Repeating device checks

Run on the development Mac:

```sh
cargo test --lib
python3 -m unittest discover -s tests -p 'test_*.py'
xcrun --sdk iphoneos clang -target arm64-apple-ios14.0 -fblocks -Os -framework CoreFoundation -framework CFNetwork -framework Network tests/interfaces.c -o build/interfaces
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

Failure tests need captures with clear protected intervals, audited the same way:

1. Kill only the verified installed provider PID and trigger fresh requests. Confirm reconnection and require no direct packets from the protected app during recovery. Record initial failures separately from successful recovery.
2. Temporarily use an unreachable proxy endpoint. Both DNS-based and literal-IP Internet requests must fail. Restore the exact private settings and reconnect; never count the deliberate protection-off cleanup interval as protected.
3. Capture continuous traffic during explicit restart, proxy changes, and All apps ↔ Selected apps changes. The overlap of protected app scopes must remain routed or blocked. A proxy switch may use either recorded proxy endpoint during the transition; pass both with `--proxy`.
4. Explicit disable must remove the owned native profile and restore normal networking. The backend must not install PF rules, change `enable_netagent`, or leave a Slipstream launchd job.
5. Close the app and check that the native session remains Connected. Verify a fresh, nonmultiplexed SSH connection through your jump host while Connected and the phone's Tailscale is off.

For existing-flow activation, start a selected test app's TCP and UDP connections while disabled, enable protection, then audit new and ongoing traffic separately. Command-line probes run over SSH never match an app rule, so they prove nothing about the app proxy. Do not infer coverage of existing sockets from a new-connection test. Expect real traffic in every capture; do not treat an empty capture as evidence, and check tcpdump's dropped-packet count.

Selected-app checks require a selected ordinary client, an unselected control, DNS, BSD TCP and URLSession/Network.framework. Safari must be labeled **Not supported** and rejected before saving an unsupported selection.

Before routing/path changes, install a bounded device-side rollback. Keep the current settings private, record exact owned profile/process IDs, and verify new LAN SSH sessions rather than relying on an existing connection. Phone-level Tailscale coexistence is not a requirement.

See [wifi-cycle.md](wifi-cycle.md) for the bounded MobileWiFi helper and its independent restoration watchdog. No active cellular service was available during the recorded validation, so a cellular handoff still requires a provisioned test device.

Raw captures contain secrets. Store them outside source control and do not paste their payloads into logs.

## SOCKS5 relay checks

Run a relay on a Mac that shares the phone's LAN, then import it as a SOCKS5 list, select it, and enable protection:

```sh
python3 tests/socks5_relay.py --bind LAN_IP --port 1080 --user u --password p
```

Repeat the HTTPS, DNS, and selected-app checks. Then send UDP from a selected app, for example a STUN request to `stun.l.google.com:19302`, and confirm the relay logs `UDP ASSOCIATE` and the app receives a reply. Rerun the relay with `--no-udp`: Test Connection must report UDP **Not relayed** and the same request must time out. `audit_per_app_capture.py` allows UDP to the proxy host; UDP from the provider to any other host is a violation.

## App checks

Build both `./scripts/build-app.sh` and `./scripts/build-app.sh iphonesimulator`. Simulator fixtures cover empty, off, and protected layouts; only the physical phone verifies privilege and routing behavior. Check light/dark appearance and accessibility text sizes, including a complete exit IP.

On-device, launch from SpringBoard; import invalid input and require a visible line-number error; import a valid list twice and confirm deduplication without a selection change. Exercise search, list filtering, selection, protection off/on, and a connectivity check. Confirm selected-proxy deletion is rejected while enabled, and the helper denies a direct call from another mobile process. Close the app and verify the native session stays protected.

Capture during proxy changes. A transition may legitimately use either the previous or new exact proxy endpoint; audit both explicitly. Exclude deliberate protection-off intervals from protected-traffic claims. Check a failed proxy while enabled, then recover by selecting a working proxy.

Latency checks: the CLI requests the check from the connected provider in both routing modes. On-device, tap **Test Connection** and compare its millisecond value with SYN→SYN/ACK timing in the physical-interface capture. A wrong selection ID must fail, and an unreachable selected proxy must yield no value after the three-second TCP timeout. Check that retesting/selection changes clear stale values, that the HTTPS exit-IP check remains independent, and that the UI stays static between tests. No temporary routing exceptions are needed.

## Packaging

Build and check both schemes, as the release workflow does:

```sh
./scripts/build.sh
python3 scripts/release.py package "$(cat VERSION)"
SLIPSTREAM_SCHEME=rootful ./scripts/build.sh
python3 scripts/release.py package "$(cat VERSION)"
for deb in build/io.github.10.slipstream_"$(cat VERSION)"_*.deb; do python3 tests/check_package.py "$deb"; done
```

On a phone, test an upgrade while protected (the provider is replaced and saved files keep their hashes), uninstall, and reinstall.
