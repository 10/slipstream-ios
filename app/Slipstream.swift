import SwiftUI
import UniformTypeIdentifiers

struct SavedProxy: Codable, Identifiable, Equatable {
    var id: UInt64
    var host: String
    var port: Int
    var username: String
    var password: String
    var type: String? = nil
    var isSocks5: Bool { type == "socks5" }
    var address: String { "\(host):\(port)" }
    var credentials: String { username.isEmpty ? "" : "\(username):\(password)" }
    var line: String { credentials.isEmpty ? address : "\(address):\(credentials)" }
}
struct SavedList: Codable, Identifiable {
    var id: UInt64
    var name: String
    var proxies: [SavedProxy]
}
struct AppRouting: Codable, Equatable {
    var mode = "all"
    var bundle_ids: [String] = []
    var summary: String { mode == "all" ? "All apps" : "\(bundle_ids.count) selected" }
}
struct InstalledApp: Decodable, Identifiable {
    var id: String
    var name: String
    var requires_all = false
}
/// An installed app's Home Screen icon. UIKit's private icon lookup can read other apps' icons
/// because this app is not sandboxed; where it is missing, a neutral tile stands in.
struct AppIcon: View {
    let id: String
    private static let cache = NSCache<NSString, UIImage>()
    private static func image(_ id: String) -> UIImage? {
        if let image = cache.object(forKey: id as NSString) { return image }
        let selector = NSSelectorFromString("_applicationIconImageForBundleIdentifier:format:scale:")
        guard let method = class_getClassMethod(UIImage.self, selector) else { return nil }
        // Format 0 is the 29-point icon Settings shows beside app names.
        typealias Lookup = @convention(c) (AnyClass, Selector, NSString, Int32, CGFloat) -> Unmanaged<UIImage>?
        let lookup = unsafeBitCast(method_getImplementation(method), to: Lookup.self)
        guard let image = lookup(UIImage.self, selector, id as NSString, 0, UIScreen.main.scale)?.takeUnretainedValue() else { return nil }
        cache.setObject(image, forKey: id as NSString)
        return image
    }
    var body: some View {
        Group {
            if let image = Self.image(id) { Image(uiImage: image).resizable() }
            else { Color(.tertiarySystemFill) }
        }
        .frame(width: 29, height: 29)
        .clipShape(RoundedRectangle(cornerRadius: 6.5, style: .continuous))
        .accessibilityHidden(true)
    }
}
struct Snapshot: Codable {
    var state: String
    var enabled: Bool
    var selected: UInt64?
    var network: String?
    var lists: [SavedList]
    var app_routing: AppRouting? = nil
    var appRouting: AppRouting { app_routing ?? AppRouting() }
    var proxy: SavedProxy? { lists.flatMap(\.proxies).first { $0.id == selected } }
}
struct Reply: Decodable {
    var ok: Bool
    var snapshot: Snapshot?
    var message: String?
    var latency_ms: UInt64?
    var udp: String?
    var apps: [InstalledApp]?
}

let slipstreamUITint = UIColor { trait in
    trait.userInterfaceStyle == .dark
        ? UIColor(red: 0.37, green: 0.85, blue: 0.82, alpha: 1)
        : UIColor(red: 0, green: 0.46, blue: 0.44, alpha: 1)
}
let slipstreamTint = Color(slipstreamUITint)

@MainActor final class TunnelModel: ObservableObject {
    @Published var snapshot: Snapshot?
    @Published var operation: String?
    @Published var error: String?
    @Published var notice: String?
    @Published var checking = false
    @Published var exitIP: String?
    @Published var latencyMS: UInt64?
    @Published var udp: String?
    @Published var checkedAt: Date?
    private var refreshing = false
    private var refreshError = false
    private var revision = 0
    var busy: Bool { operation != nil || checking }
    var protected: Bool { snapshot?.state == "protected" }

    private func request(_ payload: [String: Any]) async throws -> Reply {
        let data = try JSONSerialization.data(withJSONObject: payload)
        let text = String(decoding: data, as: UTF8.self)
        return try await Task.detached(priority: .userInitiated) {
            guard let response = text.withCString({ slipstream_request($0) }) else { throw URLError(.cannotConnectToHost) }
            defer { free(response) }
            return try JSONDecoder().decode(Reply.self, from: Data(String(cString: response).utf8))
        }.value
    }

    func refresh(allowDuringCheck: Bool = false) async {
        guard operation == nil, (!checking || allowDuringCheck), !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        #if targetEnvironment(simulator)
        if snapshot == nil {
            let mode = ProcessInfo.processInfo.environment["SLIPSTREAM_PREVIEW"] ?? "protected"
            let proxies = (0..<6).map { SavedProxy(id: UInt64($0 + 2), host: "198.51.100.\(42 + $0)", port: 3128, username: "example_user", password: "example_pass:\($0)") }
            let socks = [SavedProxy(id: 11, host: "203.0.113.18", port: 1080, username: "example_user", password: "example_pass", type: "socks5"), SavedProxy(id: 12, host: "203.0.113.19", port: 1080, username: "", password: "", type: "socks5")]
            let lists = mode == "empty" ? [] : [SavedList(id: 1, name: "Everyday", proxies: proxies), SavedList(id: 10, name: "Travel", proxies: socks)]
            snapshot = Snapshot(state: mode == "empty" || mode == "off" ? "disabled" : mode == "selected" || mode == "socks5" ? "protected" : mode, enabled: mode != "empty" && mode != "off", selected: mode == "empty" ? nil : mode == "socks5" ? 11 : 2, network: "Wi-Fi", lists: lists, app_routing: mode == "selected" ? AppRouting(mode: "selected", bundle_ids: ["com.burbn.instagram", "com.google.ios.youtube"]) : AppRouting())
        }
        return
        #else
        do {
            let result = try await request(["action": "status"])
            if let updated = result.snapshot {
                if snapshot?.selected != updated.selected || snapshot?.state != updated.state || snapshot?.appRouting != updated.appRouting {
                    revision += 1
                    clearCheck()
                }
                snapshot = updated
            }
            if !result.ok {
                refreshError = true
                error = result.message ?? "Could not read protection status."
                if result.snapshot == nil { snapshot = nil; clearCheck() }
            } else if refreshError {
                refreshError = false
                error = nil
            }
        } catch {
            refreshError = true
            self.error = "Could not read protection status. Refresh or reopen the app after jailbreaking."
            snapshot = nil
            clearCheck()
        }
        #endif
    }

    @discardableResult func perform(_ payload: [String: Any], label: String) async -> Bool {
        guard !busy else { return false }
        operation = label
        while refreshing { try? await Task.sleep(nanoseconds: 50_000_000) }
        error = nil
        refreshError = false
        notice = nil
        revision += 1
        clearCheck()
        var success = false
        let background = UIApplication.shared.beginBackgroundTask(withName: "Update Slipstream")
        defer { if background != .invalid { UIApplication.shared.endBackgroundTask(background) } }
        #if targetEnvironment(simulator)
        success = previewPerform(payload)
        #else
        do {
            let result = try await request(payload)
            if let updated = result.snapshot { snapshot = updated }
            success = result.ok
            if result.ok { notice = result.message }
            else { error = result.message ?? "The change could not be completed. Retry." }
        } catch { self.error = "The service did not return a result. Refresh to check protection before retrying." }
        #endif
        operation = nil
        if !success { await refresh() }
        UIAccessibility.post(notification: .announcement, argument: success ? (notice ?? "Updated") : error)
        return success
    }

    func installedApps() async throws -> [InstalledApp] {
        #if targetEnvironment(simulator)
        return [InstalledApp(id: "com.burbn.instagram", name: "Instagram"), InstalledApp(id: "com.google.ios.youtube", name: "YouTube"), InstalledApp(id: "com.zhiliaoapp.musically", name: "TikTok")].sorted { $0.name < $1.name }
        #else
        let reply = try await request(["action": "apps"])
        guard reply.ok, let apps = reply.apps else { throw URLError(.cannotLoadFromNetwork) }
        return apps
        #endif
    }
    private func clearCheck() { exitIP = nil; latencyMS = nil; udp = nil; checkedAt = nil }
    func checkConnection() async {
        guard protected, !busy else { return }
        checking = true
        defer { checking = false }
        while refreshing {
            do { try await Task.sleep(nanoseconds: 50_000_000) } catch { return }
        }
        guard protected, let selected = snapshot?.selected else { return }
        let currentRevision = revision
        clearCheck()
        #if targetEnvironment(simulator)
        exitIP = "203.0.113.42"; latencyMS = 42; checkedAt = Date()
        let preview = ProcessInfo.processInfo.environment
        udp = preview["SLIPSTREAM_PREVIEW_UDP"] ?? (snapshot?.proxy?.isSocks5 == true ? "relayed" : "blocked")
        return
        #else
        let latency = try? await request(["action": "test_connection", "id": selected])
        var resultIP: String?
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 12
        configuration.timeoutIntervalForResource = 15
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        do {
            let (data, response): (Data, URLResponse) = try await withCheckedThrowingContinuation { result in
                session.dataTask(with: URL(string: "https://api.ipify.org?format=json")!) { data, response, error in
                    if let data = data, let response = response { result.resume(returning: (data, response)) }
                    else { result.resume(throwing: error ?? URLError(.badServerResponse)) }
                }.resume()
            }
            struct IPResponse: Decodable { var ip: String }
            if (response as? HTTPURLResponse)?.statusCode == 200, data.count < 512 {
                let ip = try JSONDecoder().decode(IPResponse.self, from: data).ip
                var ipv4 = in_addr(), ipv6 = in6_addr()
                if inet_pton(AF_INET, ip, &ipv4) == 1 || inet_pton(AF_INET6, ip, &ipv6) == 1 { resultIP = ip }
            }
        } catch { /* A failed check never changes routing or disables protection. */ }
        await refresh(allowDuringCheck: true)
        guard currentRevision == revision, protected else { return }
        checkedAt = Date()
        exitIP = resultIP
        latencyMS = latency?.ok == true ? latency?.latency_ms : nil
        udp = latency?.ok == true ? latency?.udp : nil
        #endif
    }

    #if targetEnvironment(simulator)
    private func previewPerform(_ payload: [String: Any]) -> Bool {
        guard var value = snapshot, let action = payload["action"] as? String else { return false }
        switch action {
        case "select": value.selected = payload["id"] as? UInt64; value.enabled = true; value.state = "protected"
        case "enable", "restart": value.enabled = true; value.state = "protected"
        case "disable": value.enabled = false; value.state = "disabled"
        case "set_app_routing":
            if let routing = payload["routing"] as? [String: Any] {
                value.app_routing = AppRouting(mode: routing["mode"] as? String ?? "all", bundle_ids: routing["bundle_ids"] as? [String] ?? [])
            }
        case "import": notice = "Preview only. Import is verified on the iPhone."
        default: break
        }
        snapshot = value
        return true
    }
    #endif
}

@main struct SlipstreamApp: App {
    @StateObject private var model = TunnelModel()
    @Environment(\.scenePhase) private var phase
    init() {
        // iOS 14 action sheets take their tint from UIKit, not SwiftUI.
        if #available(iOS 15, *) {} else { UIView.appearance(whenContainedInInstancesOf: [UIAlertController.self]).tintColor = slipstreamUITint }
    }
    var body: some Scene {
        WindowGroup {
            HomeView(model: model)
                .appTint()
                .overlay(Group {
                    if phase != .active {
                        ZStack {
                            Color(.systemBackground).ignoresSafeArea()
                            Label("Slipstream", systemImage: "point.3.connected.trianglepath.dotted")
                                .font(.title2.weight(.semibold)).foregroundColor(slipstreamTint)
                        }.accessibilityHidden(true)
                    }
                })
        }
    }
}

struct HomeView: View {
    @ObservedObject var model: TunnelModel
    @Environment(\.scenePhase) private var phase
    @State private var search = ""
    @State private var listID: UInt64 = 0
    @State private var importing = false
    @State private var showingHelp = false
    @State private var managing = false
    @State private var showingApps = false
    @State private var pendingDelete: SavedProxy?
    var groups: [SavedList] { model.snapshot?.lists ?? [] }
    var visible: [SavedList] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return groups.filter { listID == 0 || $0.id == listID }.map { group in
            SavedList(id: group.id, name: group.name, proxies: group.proxies.filter {
                query.isEmpty || $0.line.localizedCaseInsensitiveContains(query) || group.name.localizedCaseInsensitiveContains(query)
            })
        }.filter { !$0.proxies.isEmpty }
    }
    var body: some View {
        Navigation {
            List {
                protection
                if let error = model.error {
                    Section {
                        Label { Text(error).font(.subheadline) } icon: { WarningSymbol() }
                        Button("Refresh Status") { Task { await model.refresh() } }.disabled(model.busy)
                    }
                }
                if let notice = model.notice {
                    Section { Text(notice).font(.subheadline).foregroundColor(.secondary) }
                }
                connection
                if #available(iOS 15, *) {} else {
                    if model.snapshot != nil && !groups.allSatisfy({ $0.proxies.isEmpty }) {
                        Section { SearchField(prompt: "Search proxies", text: $search) }
                    }
                    // Later versions filter from the toolbar.
                    if groups.count > 1 {
                        Section {
                            Picker("List", selection: $listID) {
                                Text("All Proxies").tag(UInt64(0))
                                ForEach(groups) { Text("\($0.name) (\($0.proxies.count))").tag($0.id) }
                            }
                        }
                    }
                }
                if model.snapshot == nil {
                    Section { Text(model.error == nil ? "Loading…" : "Proxies unavailable").foregroundColor(.secondary) }
                } else if groups.allSatisfy({ $0.proxies.isEmpty }) {
                    Section {
                        VStack(spacing: 8) {
                            Image(systemName: "tray.and.arrow.down").font(.largeTitle).imageScale(.large)
                                .foregroundColor(.secondary).padding(.bottom, 4).accessibilityHidden(true)
                            Text("No Proxies").font(.title2.weight(.semibold))
                            Text("Import a list to choose a proxy.").font(.subheadline).foregroundColor(.secondary)
                            Button("Import Proxies") { importing = true }.prominent().padding(.top, 12)
                        }.multilineTextAlignment(.center).frame(maxWidth: .infinity).padding(.vertical, 24)
                    }.listRowBackground(Color.clear)
                } else if visible.isEmpty {
                    Section { Text("No matches").foregroundColor(.secondary) }
                } else {
                    ForEach(visible) { group in
                        Section {
                            if #available(iOS 15, *) {
                                ForEach(group.proxies) { proxy in
                                    proxyRow(proxy)
                                        .swipeActions(allowsFullSwipe: false) {
                                            Button("Remove", role: .destructive) { pendingDelete = proxy }
                                        }
                                }
                            } else {
                                ForEach(group.proxies, content: proxyRow).onDelete { pendingDelete = $0.first.map { group.proxies[$0] } }
                            }
                        } header: {
                            HStack { Text(group.name); Spacer(); Text("\(group.proxies.count)").digits() }
                        }
                    }
                }
                #if targetEnvironment(simulator)
                Section {
                    Text("Preview data · Simulator only").font(.footnote).foregroundColor(.secondary)
                }.listRowBackground(Color.clear)
                #endif
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Slipstream")
            .navigationBarTitleDisplayMode(.inline)
            .searchDrawer($search, prompt: "Search proxies")
            .pullToRefresh { await model.refresh() }
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    MenuButton(items: options) { Image(systemName: toolbarSymbol("ellipsis")).frame(minWidth: 44, minHeight: 44) }
                    .accessibilityLabel("More options").disabled(model.busy)
                }
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    listFilter
                    Button { importing = true } label: { Label("Import", systemImage: "plus") }
                        .disabled(model.busy).accessibilityIdentifier("importProxies")
                }
            }
            .sheet(isPresented: $importing) { ImportView(model: model, suggestedName: groups.first(where: { $0.id == listID })?.name ?? "").appTint() }
            .destination(isPresented: $managing) { ListsView(model: model) }
            .destination(isPresented: $showingApps) { AppsView(model: model) }
            .sheet(isPresented: $showingHelp) { HelpView().appTint() }
            .confirmation("Remove this proxy?", item: $pendingDelete, label: { "Remove \($0.address)" }) { proxy in
                Task { await model.perform(["action": "delete_proxy", "id": proxy.id], label: "Removing proxy…") }
            }
            .onChange(of: groups.map(\.id)) { ids in if listID != 0 && !ids.contains(listID) { listID = 0 } }
            #if targetEnvironment(simulator)
            .onAppear {
                let preview = ProcessInfo.processInfo.environment
                // Pushed screens read the preview snapshot when they appear, so load it first.
                Task {
                    await model.refresh()
                    switch preview["SLIPSTREAM_PREVIEW_SHEET"] {
                    case "import", "import-socks5": importing = true
                    case "lists": managing = true
                    case "apps": showingApps = true
                    case "help": showingHelp = true
                    default: break
                    }
                }
                if let list = preview["SLIPSTREAM_PREVIEW_LIST"].flatMap(UInt64.init) { listID = list }
            }
            #endif
            .backportedTask(id: phase) { phase in
                guard phase == .active else { return }
                repeat {
                    await model.refresh()
                    if model.protected && model.checkedAt == nil { await model.checkConnection() }
                    do { try await Task.sleep(nanoseconds: 5_000_000_000) } catch { return }
                } while !Task.isCancelled
            }
        }
    }

    private var options: [MenuItem] {
        var items = [MenuItem(title: "Manage Lists", symbol: "list.bullet.rectangle") { managing = true },
                     MenuItem(title: "Help", symbol: "info.circle") { showingHelp = true }]
        if model.snapshot?.enabled == true {
            items.append(MenuItem(title: "Restart Connection", symbol: "arrow.clockwise") {
                Task { if await model.perform(["action": "restart"], label: "Restarting…") { await model.checkConnection() } }
            })
        }
        return items
    }
    private var protection: some View {
        Section {
            HStack(spacing: 12) {
                HStack(spacing: 12) {
                    Group {
                        if model.operation != nil || (model.snapshot == nil && model.error == nil) { ProgressView() }
                        else { Image(systemName: statusSymbol).font(.title).foregroundColor(statusColor) }
                    }.frame(width: 36)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(statusTitle).font(.title3.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
                        if let subtitle = statusSubtitle { Text(subtitle).font(.subheadline).foregroundColor(.secondary) }
                    }
                }.accessibilityElement(children: .combine)
                Spacer(minLength: 0)
                Toggle("Protection", isOn: Binding(get: {
                    model.snapshot?.enabled == true
                }, set: { enabled in
                    Task { if await model.perform(["action": enabled ? "enable" : "disable"], label: enabled ? "Enabling…" : "Disabling…"), enabled { await model.checkConnection() } }
                }))
                .labelsHidden().disabled(model.busy || model.snapshot == nil || (model.snapshot?.selected == nil && model.snapshot?.enabled != true))
                .accessibilityLabel("Protection").accessibilityIdentifier("protectionToggle")
            }.padding(.vertical, 6)
            if let proxy = model.snapshot?.proxy {
                DetailRow(label: "Proxy", caption: proxy.isSocks5 ? "SOCKS5" : nil) {
                    Text(proxy.address).font(.system(.body, design: .monospaced)).selectableText()
                }
            }
            Button { showingApps = true } label: {
                HStack {
                    Text("Apps").foregroundColor(.primary)
                    Spacer()
                    Text(model.snapshot?.appRouting.summary ?? "All apps").foregroundColor(.secondary)
                    Image(systemName: "chevron.forward").font(.footnote.weight(.semibold)).foregroundColor(Color(.tertiaryLabel))
                }
            }.disabled(model.busy || model.snapshot == nil).accessibilityIdentifier("appRouting")
        }
    }
    /// The connection check is a separate fact from protection, so it has its own section.
    @ViewBuilder private var connection: some View {
        if model.protected && model.operation == nil {
            Section {
                if !model.checking, model.checkedAt != nil {
                    DetailRow(label: "Exit IP") {
                        if let ip = model.exitIP { Text(ip).font(.system(.body, design: .monospaced)).selectableText() }
                        else { Label { Text("Check failed") } icon: { WarningSymbol() } }
                    }
                    DetailRow(label: "Latency") { Text(model.latencyMS.map { "\($0) ms" } ?? "Unavailable").font(Font.body.monospacedDigit()) }
                    if let udp = udpValue { DetailRow(label: "UDP") { Text(udp) } }
                }
                Button { Task { await model.checkConnection() } } label: {
                    HStack {
                        Text(model.checking ? "Checking…" : "Test Connection")
                        Spacer()
                        if model.checking { ProgressView() }
                    }
                }.disabled(model.checking).accessibilityIdentifier("testConnection")
            } header: { Text("Connection") } footer: {
                if !model.checking, let date = model.checkedAt {
                    Text("Checked at \(DateFormatter.localizedString(from: date, dateStyle: .none, timeStyle: .short))."
                         + (model.udp == "unsupported" ? " This proxy doesn’t relay UDP, so calls and games that need it may fail." : ""))
                }
            }
        }
    }
    private var udpValue: String? {
        switch model.udp {
        case "relayed": return "Relayed"
        case "unsupported": return "Not relayed"
        case "blocked": return "Blocked"
        default: return nil
        }
    }
    private var statusTitle: String {
        switch model.snapshot?.state {
        case "protected": return "Protected"
        case "starting": return "Starting…"
        case "unavailable": return "Protection unavailable"
        case "disabled": return "Protection off"
        default: return model.error == nil ? "Checking…" : "Status unavailable"
        }
    }
    private var statusSubtitle: String? {
        if let operation = model.operation { return operation }
        guard model.snapshot?.enabled == true else { return nil }
        return model.snapshot?.network
    }
    private var statusSymbol: String {
        switch model.snapshot?.state {
        case "protected": return "checkmark.shield.fill"
        case "disabled": return "shield.slash"
        case "starting": return "shield.lefthalf.fill"
        default: return "exclamationmark.shield.fill"
        }
    }
    private var statusColor: Color {
        switch model.snapshot?.state {
        case "protected", "starting": return slipstreamTint
        case "disabled": return .secondary
        default: return .orange
        }
    }
    private var typeBadge: some View {
        Text("SOCKS5").font(.caption2.weight(.semibold)).foregroundColor(.secondary)
            .padding(.horizontal, 7).padding(.vertical, 3)
            .background(Capsule().fill(Color(.tertiarySystemFill)))
            .accessibilityLabel("SOCKS5 proxy")
    }
    /// Later versions filter lists from the toolbar; iOS 14 keeps an inline picker.
    @ViewBuilder private var listFilter: some View {
        if #available(iOS 15, *) {
            if groups.count > 1 {
                Menu {
                    Picker("Show", selection: $listID) {
                        Text("All Proxies").tag(UInt64(0))
                        ForEach(groups) { Text($0.name).tag($0.id) }
                    }
                } label: {
                    Image(systemName: listID == 0 ? toolbarSymbol("line.3.horizontal.decrease") : "line.3.horizontal.decrease.circle.fill")
                }
                .accessibilityLabel("Filter lists")
                .accessibilityValue(groups.first { $0.id == listID }?.name ?? "All proxies")
            }
        }
    }
    private func proxyRow(_ proxy: SavedProxy) -> some View {
        let selected = proxy.id == model.snapshot?.selected
        return Button { Task { if await model.perform(["action": "select", "id": proxy.id], label: "Switching…") { await model.checkConnection() } } } label: {
            HStack(spacing: 12) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.title3).foregroundColor(selected ? slipstreamTint : Color(.tertiaryLabel))
                VStack(alignment: .leading, spacing: 5) {
                    Text(proxy.address).font(.system(.body, design: .monospaced)).foregroundColor(.primary)
                    if !proxy.credentials.isEmpty {
                        Text(proxy.credentials).font(.system(.caption, design: .monospaced))
                            .foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 0)
                if proxy.isSocks5 { typeBadge }
            }.padding(.vertical, 4).frame(minHeight: 44).contentShape(Rectangle())
        }.buttonStyle(.plain).disabled(model.busy)
        .accessibilityElement(children: .combine)
        .accessibilityHint("Connect")
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}

struct ImportView: View {
    @ObservedObject var model: TunnelModel
    let suggestedName: String
    @Environment(\.presentationMode) private var presentation
    @State private var name = ""
    @State private var type = "http"
    @State private var text = ""
    @State private var filePicker = false
    @State private var localError: String?
    var body: some View {
        Navigation {
            Form {
                if let error = localError {
                    Section { Label { Text(error).font(.subheadline) } icon: { WarningSymbol() } }
                }
                Section {
                    TextField("List name", text: $name).autocapitalization(.words).disableAutocorrection(true).accessibilityIdentifier("listName")
                    Picker("Type", selection: $type) {
                        Text("HTTP").tag("http")
                        Text("SOCKS5").tag("socks5")
                    }.pickerStyle(.segmented).accessibilityIdentifier("proxyType")
                } footer: {
                    Text(type == "socks5" ? "SOCKS5 proxies can also relay UDP, such as calls and QUIC, when the proxy supports it." : "HTTP proxies carry TCP only. UDP is blocked.")
                }
                Section {
                    ZStack(alignment: .topLeading) {
                        TextEditor(text: $text)
                            .font(.system(.body, design: .monospaced)).frame(minHeight: 170)
                            .autocapitalization(.none).disableAutocorrection(true)
                            .accessibilityLabel("Proxy list").accessibilityIdentifier("proxyText")
                        if text.isEmpty {
                            // TextEditor has no placeholder; this sits on its first line.
                            Text("203.0.113.10:8080:user:pass").font(.system(.body, design: .monospaced))
                                .foregroundColor(Color(.placeholderText)).padding(.top, 8).padding(.leading, 5)
                                .allowsHitTesting(false).accessibilityHidden(true)
                        }
                    }
                    HStack(spacing: 12) {
                        if #available(iOS 16, *) {
                            PasteButton(payloadType: String.self) { values in text = values.joined(separator: "\n"); localError = nil }
                                .labelStyle(.titleAndIcon).tint(slipstreamTint).buttonBorderShape(.capsule)
                        } else {
                            Button { if let value = UIPasteboard.general.string { text = value; localError = nil } } label: {
                                Label("Paste", systemImage: "doc.on.clipboard")
                            }.capsule(prominent: true)
                        }
                        Button { filePicker = true } label: { Label("Choose File", systemImage: "folder") }.capsule()
                        Spacer(minLength: 0)
                    }.padding(.vertical, 6)
                } header: { Text("Proxies") } footer: {
                    Text("One per line, as ip:port:user:pass or ip:port.")
                }
            }
            .navigationTitle("Import Proxies").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { text = ""; presentation.wrappedValue.dismiss() }.disabled(model.busy) }
                ToolbarItem(placement: .confirmationAction) {
                    Button(model.busy ? "Importing…" : "Import") {
                        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                        Task {
                            if await model.perform(["action": "import", "name": name, "type": type, "text": text], label: "Importing proxies…") { text = ""; presentation.wrappedValue.dismiss() }
                            else { localError = model.error }
                        }
                    }.font(Font.body.weight(.semibold)).disabled(model.busy || text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .dismissDisabled(model.busy)
            .onAppear { name = suggestedName
                #if targetEnvironment(simulator)
                if ProcessInfo.processInfo.environment["SLIPSTREAM_PREVIEW_SHEET"] == "import-socks5" { type = "socks5" }
                #endif
            }
            .fileImporter(isPresented: $filePicker, allowedContentTypes: [.plainText, .text]) { result in
                do {
                    let url = try result.get()
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size <= 1024 * 1024 else { localError = "Choose a text file smaller than 1 MB."; return }
                    let data = try Data(contentsOf: url)
                    guard data.count <= 1024 * 1024, let imported = String(data: data, encoding: .utf8) else { localError = "Choose a UTF-8 text file smaller than 1 MB."; return }
                    text = imported
                    if name.isEmpty { name = String(url.deletingPathExtension().lastPathComponent.prefix(40)) }
                    localError = nil
                } catch { localError = "The file could not be opened. Choose another file or paste the list." }
            }
        }
    }
}

struct ListsView: View {
    @ObservedObject var model: TunnelModel
    @State private var renaming: SavedList?
    @State private var newName = ""
    @State private var deleting: SavedList?
    var body: some View {
        List {
            if let error = model.error { Section { Label { Text(error).font(.subheadline) } icon: { WarningSymbol() } } }
            if model.snapshot?.lists.isEmpty == true { Text("No lists").foregroundColor(.secondary) }
            ForEach(model.snapshot?.lists ?? []) { group in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(group.name)
                        Text(group.proxies.count == 1 ? "1 proxy" : "\(group.proxies.count) proxies").font(.subheadline).foregroundColor(.secondary)
                    }
                    Spacer()
                    MenuButton(items: [
                        MenuItem(title: "Rename", symbol: "pencil") { newName = group.name; renaming = group },
                        MenuItem(title: "Delete List", symbol: "trash", destructive: true) { deleting = group },
                    ]) { Image(systemName: "ellipsis.circle").frame(minWidth: 44, minHeight: 44) }
                        .accessibilityLabel("Manage \(group.name)").disabled(model.busy)
                }
            }
        }.listStyle(.insetGrouped).navigationTitle("Manage Lists").navigationBarTitleDisplayMode(.inline)
        .textPrompt("Rename List", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } }), text: $newName, placeholder: "List name") {
            if let group = renaming { Task { await model.perform(["action": "rename_list", "id": group.id, "name": newName], label: "Renaming list…") } }; renaming = nil
        }
        .confirmation("Delete this list?", item: $deleting, label: { "Delete \($0.name)" }) { group in
            Task { await model.perform(["action": "delete_list", "id": group.id], label: "Deleting list…") }
        }
    }
}

struct AppsView: View {
    @ObservedObject var model: TunnelModel
    @Environment(\.presentationMode) private var presentation
    @State private var routing = AppRouting()
    @State private var original = AppRouting()
    @State private var apps: [InstalledApp] = []
    @State private var search = ""
    @State private var loading = true
    @State private var failed = false
    var visible: [InstalledApp] { apps.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.id.localizedCaseInsensitiveContains(search) } }
    var missing: [String] { routing.bundle_ids.filter { id in !apps.contains { $0.id == id } } }
    var unsupported: Bool { apps.contains { $0.requires_all && routing.bundle_ids.contains($0.id) } }
    var body: some View {
        Group {
            if routing.mode == "selected" { content.searchDrawer($search, prompt: "Search apps") }
            else { content }
        }
        .navigationTitle("Apps").navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(model.operation == nil ? "Save" : "Saving…") {
                    Task {
                        let value: [String: Any] = ["mode": routing.mode, "bundle_ids": routing.bundle_ids.sorted()]
                        if await model.perform(["action": "set_app_routing", "routing": value], label: "Saving…") { presentation.wrappedValue.dismiss() }
                    }
                }.disabled(model.busy || routing == original || (routing.mode == "selected" && (routing.bundle_ids.isEmpty || loading || failed || !missing.isEmpty || unsupported)))
            }
        }
        .backportedTask {
            original = model.snapshot?.appRouting ?? AppRouting()
            routing = original
            await load()
        }
    }
    private var content: some View {
        List {
            Section {
                Picker("Route", selection: $routing.mode) {
                    Text("All apps").tag("all")
                    Text("Selected apps").tag("selected")
                }.pickerStyle(.segmented).disabled(model.busy).accessibilityIdentifier("routingMode")
            }
            if let error = model.error { Section { Label { Text(error).font(.subheadline) } icon: { WarningSymbol() } } }
            if routing.mode == "selected" {
                if loading { Section { ProgressView("Loading apps…") } }
                else if failed {
                    Section { Text("Could not load apps."); Button("Retry") { Task { await load() } } }
                } else {
                    if #available(iOS 15, *) {} else { Section { SearchField(prompt: "Search apps", text: $search) } }
                    Section {
                        if visible.isEmpty { Text("No matches").foregroundColor(.secondary) }
                        ForEach(visible) { app in
                            selectionRow(name: app.name, id: app.id, requiresAll: app.requires_all)
                        }
                    } header: { Text("\(routing.bundle_ids.count) selected") }
                      footer: { Text("Only apps you installed are listed. Other apps, including Apple’s, use your normal IP.") }
                    if !missing.isEmpty {
                        Section(header: Text("Unavailable")) { ForEach(missing, id: \.self) { id in selectionRow(name: id, id: id) } }
                    }
                }
            }
        }.listStyle(.insetGrouped)
    }
    private func selectionRow(name: String, id: String, requiresAll: Bool = false) -> some View {
        let selected = routing.bundle_ids.contains(id)
        return Button {
            if selected { routing.bundle_ids.removeAll { $0 == id } }
            else { routing.bundle_ids.append(id); routing.bundle_ids.sort() }
        } label: {
            HStack(spacing: 12) {
                // Dimmed with the name when the app cannot be selected.
                AppIcon(id: id).opacity(requiresAll && !selected ? 0.4 : 1)
                VStack(alignment: .leading, spacing: 3) {
                    Text(name).foregroundColor(.primary).fixedSize(horizontal: false, vertical: true)
                    if requiresAll { Text("Not supported").font(.caption).foregroundColor(.secondary) }
                }
                Spacer(minLength: 8)
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.title3).foregroundColor(selected ? slipstreamTint : Color(.tertiaryLabel))
            }.frame(minHeight: 44).contentShape(Rectangle())
        }.buttonStyle(.plain).disabled(model.busy || (requiresAll && !selected))
         .accessibilityAddTraits(selected ? .isSelected : [])
    }
    private func load() async {
        loading = true; failed = false
        do { apps = try await model.installedApps() }
        catch { failed = true }
        loading = false
    }
}

struct HelpView: View {
    @Environment(\.presentationMode) private var presentation
    var body: some View {
        Navigation {
            List {
                Section(header: Text("Protection")) {
                    Text("Runs even when the app is closed. Switching proxies or failing a connection check never allows protected apps to connect directly.")
                    Text("Exit IP is verified by ipify.org. Turn protection off to use your normal connection.")
                    Text("Proxy latency measures a fresh TCP handshake to the selected proxy. For SOCKS5 proxies, UDP reports whether the proxy grants a UDP relay. Test connection refreshes both; they are not continuously monitored.")
                }
                Section(header: Text("Apps")) {
                    Text("All apps protects every app you installed; an app installed later is included when protection next restarts. Selected apps protects your choices. Apple’s apps, including Safari, and system services use your normal connection. Slipstream’s connection check is always included.")
                    Text("iOS manages app routing and reconnection. Closing Slipstream does not stop protection.")
                }
                Section(header: Text("Traffic")) {
                    Text("Protected apps’ TCP and DNS use the selected proxy. With an HTTP proxy, other UDP, including QUIC, is blocked. A SOCKS5 proxy that relays UDP also carries calls, games and QUIC. HTTPS stays encrypted.")
                    Text("DNS requires CONNECT to TCP port 53. Protected apps reach local network addresses through the proxy too. SSH to the phone is not affected.")
                }
                Section(header: Text("After a reboot")) { Text("Re-jailbreak, then confirm protection before using other apps.") }
                Section { Text("Slipstream \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") · iPhone").foregroundColor(.secondary) }
            }.navigationTitle("Help").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { presentation.wrappedValue.dismiss() } } }
        }
    }
}

/// A label and its value, as in Settings. At accessibility text sizes the value moves below the label.
struct DetailRow<Value: View>: View {
    let label: String
    var caption: String? = nil
    @ViewBuilder var value: Value
    @Environment(\.sizeCategory) private var textSize
    var body: some View {
        Group {
            if textSize.isAccessibilityCategory {
                VStack(alignment: .leading, spacing: 4) { title; value.foregroundColor(.secondary) }
            } else {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    title
                    Spacer(minLength: 0)
                    value.foregroundColor(.secondary).multilineTextAlignment(.trailing)
                }
            }
        }.accessibilityElement(children: .combine)
    }
    private var title: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
            if let caption = caption { Text(caption).font(.caption).foregroundColor(.secondary) }
        }
    }
}

struct WarningSymbol: View {
    var body: some View { Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.orange) }
}

// MARK: iOS 14 compatibility. Later versions keep their native presentation.

struct Navigation<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        if #available(iOS 16, *) { NavigationStack { content } }
        else { NavigationView { content }.navigationViewStyle(StackNavigationViewStyle()) }
    }
}

struct MenuItem {
    let title: String
    let symbol: String
    var destructive = false
    let action: () -> Void
}

/// A native menu. iOS 14 toolbar content can neither open a menu nor present SwiftUI
/// sheets reliably, so there it presents a UIKit action sheet from the key window.
struct MenuButton<Content: View>: View {
    let items: [MenuItem]
    @ViewBuilder var label: Content
    var body: some View {
        if #available(iOS 15, *) {
            Menu {
                ForEach(items.indices, id: \.self) { index in
                    Button(role: items[index].destructive ? .destructive : nil, action: items[index].action) {
                        Label(items[index].title, systemImage: items[index].symbol)
                    }
                }
            } label: { label }
        } else {
            Button {
                let sheet = UIAlertController(title: nil, message: nil, preferredStyle: .actionSheet)
                for item in items { sheet.addAction(UIAlertAction(title: item.title, style: item.destructive ? .destructive : .default) { _ in item.action() }) }
                sheet.addAction(UIAlertAction(title: "Cancel", style: .cancel))
                var top = UIApplication.shared.windows.first { $0.isKeyWindow }?.rootViewController
                while let presented = top?.presentedViewController { top = presented }
                top?.present(sheet, animated: true)
            } label: { label }.buttonStyle(.borderless)
        }
    }
}

/// iOS 14 has no search drawer; this row filters the same results inline.
struct SearchField: View {
    let prompt: String
    @Binding var text: String
    var body: some View {
        HStack {
            Image(systemName: "magnifyingglass").foregroundColor(.secondary)
            TextField(prompt, text: $text).autocapitalization(.none).disableAutocorrection(true)
        }
    }
}

/// `task(id:)`: runs on appear, restarts when `id` changes, and cancels on disappear.
/// iOS 14 `onChange` closures see pre-change captures, so the action receives the new `id`.
/// The stack keeps a `Group`'s switching branches from each re-triggering `onAppear`.
private struct BackportedTask<ID: Equatable>: ViewModifier {
    let id: ID
    let action: @MainActor (ID) async -> Void
    @State private var task: Task<Void, Never>?
    func body(content: Content) -> some View {
        ZStack { content }.onAppear { restart(id) }.onChange(of: id, perform: restart).onDisappear { task?.cancel() }
    }
    private func restart(_ id: ID) {
        task?.cancel()
        task = Task { await action(id) }
    }
}

/// iOS 26 draws toolbar buttons inside glass circles, so their symbols drop the circle.
func toolbarSymbol(_ name: String) -> String {
    if #available(iOS 26, *) { return name } else { return name + ".circle" }
}

extension View {
    @ViewBuilder func appTint() -> some View {
        if #available(iOS 15, *) { tint(slipstreamTint) }
        else { accentColor(slipstreamTint).toggleStyle(SwitchToggleStyle(tint: slipstreamTint)) }
    }
    @ViewBuilder func backportedTask<ID: Equatable>(id: ID, _ action: @escaping @MainActor @Sendable (ID) async -> Void) -> some View {
        if #available(iOS 15, *) { task(id: id) { await action(id) } } else { modifier(BackportedTask(id: id, action: action)) }
    }
    func backportedTask(_ action: @escaping @MainActor @Sendable () async -> Void) -> some View { backportedTask(id: 0) { _ in await action() } }
    @ViewBuilder func destination<Destination: View>(isPresented: Binding<Bool>, @ViewBuilder _ destination: () -> Destination) -> some View {
        if #available(iOS 16, *) { navigationDestination(isPresented: isPresented, destination: destination) }
        else { background(NavigationLink(destination: destination(), isActive: isPresented) { EmptyView() }.hidden()) }
    }
    @ViewBuilder func searchDrawer(_ text: Binding<String>, prompt: String) -> some View {
        if #available(iOS 15, *) { searchable(text: text, placement: .navigationBarDrawer(displayMode: .always), prompt: prompt) } else { self }
    }
    @ViewBuilder func pullToRefresh(_ action: @escaping @Sendable () async -> Void) -> some View {
        if #available(iOS 15, *) { refreshable(action: action) } else { self }
    }
    @ViewBuilder func selectableText() -> some View {
        if #available(iOS 15, *) { textSelection(.enabled) } else { self }
    }
    @ViewBuilder func digits() -> some View {
        if #available(iOS 15, *) { monospacedDigit() } else { self }
    }
    /// Paired capsule buttons that share a row; iOS 14 has no bordered styles.
    @ViewBuilder func capsule(prominent: Bool = false) -> some View {
        if #available(iOS 15, *) {
            if prominent { buttonStyle(.borderedProminent).buttonBorderShape(.capsule) }
            else { buttonStyle(.bordered).buttonBorderShape(.capsule) }
        } else { buttonStyle(.borderless) }
    }
    @ViewBuilder func prominent() -> some View {
        if #available(iOS 15, *) { buttonStyle(.borderedProminent).controlSize(.large) } else { self }
    }
    @ViewBuilder func dismissDisabled(_ disabled: Bool) -> some View {
        if #available(iOS 15, *) { interactiveDismissDisabled(disabled) } else { self }
    }
    /// A destructive confirmation; iOS 14 lacks confirmation dialogs and uses the equivalent action sheet.
    @ViewBuilder func confirmation<Item: Identifiable>(_ title: String, item: Binding<Item?>, label: @escaping (Item) -> String, perform: @escaping (Item) -> Void) -> some View {
        if #available(iOS 15, *) {
            confirmationDialog(title, isPresented: Binding(get: { item.wrappedValue != nil }, set: { if !$0 { item.wrappedValue = nil } }), titleVisibility: .visible) {
                if let value = item.wrappedValue {
                    Button(label(value), role: .destructive) { perform(value); item.wrappedValue = nil }
                }
            }
        } else {
            actionSheet(item: item) { value in
                ActionSheet(title: Text(title), buttons: [.destructive(Text(label(value))) { perform(value) }, .cancel()])
            }
        }
    }
    /// A text-field alert. Alerts before iOS 16 cannot hold a text field, so those use a small sheet.
    @ViewBuilder func textPrompt(_ title: String, isPresented: Binding<Bool>, text: Binding<String>, placeholder: String, save: @escaping () -> Void) -> some View {
        if #available(iOS 16, *) {
            alert(title, isPresented: isPresented) {
                TextField(placeholder, text: text)
                Button("Cancel", role: .cancel) {}
                Button("Save", action: save)
            }
        } else {
            sheet(isPresented: isPresented) {
                NavigationView {
                    Form { TextField(placeholder, text: text) }
                        .navigationTitle(title).navigationBarTitleDisplayMode(.inline)
                        .toolbar {
                            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { isPresented.wrappedValue = false } }
                            ToolbarItem(placement: .confirmationAction) { Button("Save", action: save) }
                        }
                }.appTint()
            }
        }
    }
}
