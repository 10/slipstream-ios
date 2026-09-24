# Wi-Fi cycle test helper

Built for native arm64 iOS 15+. No private framework link is needed: MobileWiFi symbols are loaded dynamically and checked before any operation. The default requested command must be explicit; `status` never calls SetPower.

Source evidence:

- Maize declarations: https://github.com/andrewwiik/Maize/blob/1f22b9e8887cbc3ff8dd19712bf51dbb02d9a1d8/Modules/ConnectivityModule/MZEConnectivityWiFiViewController.m lines 17-27 define GetPower(void*) -> int, SetPower(void*, int) -> void, Create(CFAllocatorRef, int) -> void*, ScheduleWithRunLoop, CopyCurrentNetwork.
- ProxySwitcher create/devices/current-network ownership: https://github.com/mukeran/proxyswitcher-ios/blob/598ed8fa3e5cc8732dfa9317067728d5f4210fa2/Shared/PSProxyManager%2BSystem.inc
- ProxySwitcher entitlement precedent: https://github.com/mukeran/proxyswitcher-ios/blob/598ed8fa3e5cc8732dfa9317067728d5f4210fa2/Entitlements/jailbreak.plist
- iPhoneOS18.5 SDK export list confirms these function symbols exist: https://github.com/xybp888/iOS-SDKs/blob/ad607cb07fe4ad1c9b91cf970bd228c2a9253207/iPhoneOS18.5.sdk/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi.tbd

These are private ABI signatures from source projects and SDK exports, not documented Apple public API. Device `status` execution is required to establish runtime availability.

Build:

    xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -Os -Wall -Wextra -Werror -framework CoreFoundation wifi-cycle.c -o wifi-cycle

Sign with the included entitlements using the existing jailbreak signing tool, install both executable and entitlement output via the established device workflow, then:

    wifi-cycle status
    wifi-cycle cycle 8
    wifi-cycle on

Run cycle detached from network-dependent SSH input/output, for example:

    nohup /absolute/device/path/wifi-cycle cycle 8 </dev/null >/var/tmp/slipstream-wifi-cycle.log 2>&1 &

Cycle requires Wi-Fi already powered on. It execs an independent session watchdog and waits for its readiness byte before calling SetPower(0). Main re-enables after N seconds; watchdog also re-enables at N+5 seconds even if main exits/crashes/is killed. HUP and SIGPIPE do not prevent restoration. TERM/INT interrupt the wait and expedite power restoration. Reconnection is observed for up to 20 seconds. Nonzero cycle exit means no power-off was observed, power did not restore, or association was not observed. Output omits SSID/network contents.

A reboot or killing both processes defeats a userspace timed restoration; the parent still retains its separate routing rollback/recovery mechanism.
