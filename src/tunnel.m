// The app proxy's exact-owned Network Extension configuration, its session and provider messages.
// NEConfiguration/NEVPNApp signatures: AirKeeper 9be334a6eaee8d086708ee4d89963d229a8684cf.
// Protocol initializer/application getters: nst/iOS-Runtime-Headers; runtime-checked.
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <objc/message.h>
#import "../provider/ProviderInterface.h"
#include <fcntl.h>
#include <limits.h>
extern int proc_listpids(uint32_t,uint32_t,void *,int);
extern int proc_pidpath(int,void *,uint32_t);
extern int proc_name(int,void *,uint32_t);
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <xpc/xpc.h>
// Signatures from Apple configd SCNetworkConnection.c.
extern void *ne_session_create(const unsigned char *, int);
extern void ne_session_get_status(void *, dispatch_queue_t, void (^)(int));
extern void ne_session_start_with_options(void *, xpc_object_t);
extern void ne_session_send_barrier(void *);
extern void ne_session_release(void *);

static NSString *const AppID = @"local.slipstream.app";
static NSString *const ProviderID = @"local.slipstream.app.proxy";
static const char *Journal = SLIPSTREAM_PREFIX "/etc/slipstream/tunnel.uuid";
static const char *ProviderPath = SLIPSTREAM_PREFIX "/Applications/Slipstream.app/PlugIns/AppProxyProvider.appex/AppProxyProvider";
// NEVPNApp tunnel type of an app proxy, and ne_session type of a per-app VPN.
static const int AppProxyTunnel = 2, PerAppSession = 2;
// ne_session status values: invalid 0, disconnected 1, connected 3.
static const int SessionDisconnected = 1, SessionConnected = 3;

@interface NSObject (ResearchPrivateAPI)
+ (id)sharedManagerForAllUsers;
- (id)initWithName:(NSString *)name grade:(NSInteger)grade;
- (id)initWithSigningIdentifier:(NSString *)identifier;
- (id)initWithPluginType:(NSString *)type;
- (void)loadConfigurationsWithCompletionQueue:(dispatch_queue_t)queue handler:(void (^)(NSArray *, NSError *))handler;
- (void)saveConfiguration:(id)configuration withCompletionQueue:(dispatch_queue_t)queue handler:(void (^)(NSError *))handler;
- (void)removeConfiguration:(id)configuration withCompletionQueue:(dispatch_queue_t)queue handler:(void (^)(NSError *))handler;
@end

static void fail(const char *message) __attribute__((noreturn));
static void fail(const char *message) { @throw [NSException exceptionWithName:@"Slipstream" reason:[NSString stringWithUTF8String:message] userInfo:nil]; }
static BOOL has(id value, NSString *selector) { return [value respondsToSelector:NSSelectorFromString(selector)]; }
static id get(id value, NSString *selector) {
    if (!has(value, selector)) fail("Required Network Extension getter is unavailable.");
    return ((id (*)(id, SEL))objc_msgSend)(value, NSSelectorFromString(selector));
}
static void put(id value, NSString *selector, id argument) {
    if (!has(value, selector)) fail("Required Network Extension setter is unavailable.");
    ((void (*)(id, SEL, id))objc_msgSend)(value, NSSelectorFromString(selector), argument);
}
static void number(id value, NSString *selector, NSInteger argument) {
    if (!has(value, selector)) fail("Required Network Extension setter is unavailable.");
    ((void (*)(id, SEL, NSInteger))objc_msgSend)(value, NSSelectorFromString(selector), argument);
}
// iOS can take several seconds to answer while it relaunches its Network Extension daemons,
// as under memory pressure; 6-10 s answers were measured on the XS.
static void waitFor(dispatch_semaphore_t done) {
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC))) fail("operation timeout; state uncertain, retain UUID journal");
}
// Runs a configuration manager call and waits for its completion handler.
static void call(void (^start)(dispatch_queue_t queue, void (^done)(NSError *error))) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSError *failure = nil;
    start(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(NSError *error) { failure = error; dispatch_semaphore_signal(done); });
    waitFor(done);
    if (failure) fail([[NSString stringWithFormat:@"Network Extension operation failed (%@ %ld).", failure.domain, (long)failure.code] UTF8String]);
}
static NSArray *load(id manager) {
    __block NSArray *result = nil;
    call(^(dispatch_queue_t queue, void (^done)(NSError *)) {
        [manager loadConfigurationsWithCompletionQueue:queue handler:^(NSArray *configs, NSError *error) { result = configs; done(error); }];
    });
    if (result && ![result isKindOfClass:NSArray.class]) fail("unexpected configuration collection");
    return result ?: @[];
}
static void save(id manager, id config) {
    call(^(dispatch_queue_t queue, void (^done)(NSError *)) { [manager saveConfiguration:config withCompletionQueue:queue handler:done]; });
}
static void removeConfiguration(id manager, id config) {
    call(^(dispatch_queue_t queue, void (^done)(NSError *)) { [manager removeConfiguration:config withCompletionQueue:queue handler:done]; });
}
static NSString *nameFor(NSUUID *uuid) { return [AppID stringByAppendingFormat:@".%@", uuid.UUIDString]; }
// Fails unless the configuration is Slipstream's app proxy.
static id appProxy(id config) {
    id vpn = get(config, @"appVPN");
    if (!vpn || !has(vpn, @"tunnelType")) fail("unexpected tunnel type");
    NETunnelProviderProtocol *protocol = get(vpn, @"protocol");
    NSInteger type = ((NSInteger (*)(id, SEL))objc_msgSend)(vpn, NSSelectorFromString(@"tunnelType"));
    if (type != AppProxyTunnel || ![protocol.providerBundleIdentifier isEqual:ProviderID]) fail("provider mismatch");
    return vpn;
}
// Deadlines count awake time: a sleeping phone pauses iOS and this process alike.
static double awakeSeconds(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1e9; }
static void *openSession(NSUUID *uuid) {
    unsigned char bytes[16];
    [uuid getUUIDBytes:bytes];
    void *session = ne_session_create(bytes, PerAppSession);
    if (!session) fail("session unavailable");
    return session;
}
static int sessionStatus(NSUUID *uuid) {
    void *handle = openSession(uuid);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block int current = -1;
    ne_session_get_status(handle, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(int value) { current = value; dispatch_semaphore_signal(done); });
    waitFor(done);
    ne_session_release(handle);
    return current;
}
static void startCommand(NSUUID *uuid) {
    void *handle = openSession(uuid);
    ne_session_start_with_options(handle, NULL);
    ne_session_send_barrier(handle);
    ne_session_release(handle);
}
static void saveJournal(NSUUID *uuid) {
    int fd = open(Journal, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) fail("cannot create journal");
    NSData *data = [[uuid.UUIDString stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (write(fd, data.bytes, data.length) != (ssize_t)data.length || fsync(fd)) fail("journal write failed");
    close(fd);
}
static NSUUID *readJournal(void) {
    int fd = open(Journal, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) fail("cannot open UUID journal");
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != 0 || (info.st_mode & 077) || info.st_size != 37) fail("UUID journal must be a root-owned mode-600 regular file with one UUID");
    char text[38] = {0};
    ssize_t size = read(fd, text, 37);
    close(fd);
    if (size != 37 || text[36] != '\n') fail("invalid UUID journal");
    text[36] = 0;
    NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:text]];
    if (!uuid) fail("invalid UUID journal");
    return uuid;
}
static BOOL enabled(id vpn) {
    NSString *selector = has(vpn, @"isEnabled") ? @"isEnabled" : @"enabled";
    if (!has(vpn, selector)) fail("VPN enabled state is unavailable.");
    return ((BOOL (*)(id, SEL))objc_msgSend)(vpn, NSSelectorFromString(selector));
}

// The configuration the UUID journal names, if it exists. Any other configuration under
// Slipstream's name is refused.
typedef struct { id manager; id config; NSUUID *uuid; } Owned;
static Owned owned(void) {
    Class managerClass = NSClassFromString(@"NEConfigurationManager");
    if (!has(managerClass, @"sharedManagerForAllUsers")) fail("Network Extension configuration is unavailable.");
    Owned owned = {[managerClass sharedManagerForAllUsers], nil, access(Journal, F_OK) == 0 ? readJournal() : nil};
    for (id candidate in load(owned.manager)) {
        if (owned.uuid && [get(candidate, @"identifier") isEqual:owned.uuid]) {
            if (![get(candidate, @"name") isEqual:nameFor(owned.uuid)]) fail("configuration identity mismatch; refusing operation");
            owned.config = candidate;
        } else if ([get(candidate, @"name") hasPrefix:[AppID stringByAppendingString:@"."]]) fail("An unrecognized Slipstream configuration exists. Its UUID journal is required.");
    }
    return owned;
}

// Calls body for each running provider, with whether it runs the installed executable. An
// upgrade replaces the executable; providers started earlier no longer resolve their path, so
// those are matched by name.
static void eachProvider(void (^body)(int pid, BOOL installed)) {
    char executable[PATH_MAX];
    if (!realpath(ProviderPath, executable)) fail("The app proxy provider is not installed.");
    int pids[8192], size = proc_listpids(1, 0, pids, sizeof(pids));
    if (size <= 0 || size >= (int)sizeof(pids)) fail("Could not inspect the app proxy provider.");
    for (int i = 0; i < size / (int)sizeof(int); i++) {
        char path[PATH_MAX], name[64];
        if (pids[i] <= 0) continue;
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0) {
            if (!strcmp(path, executable)) body(pids[i], YES);
        } else if (proc_name(pids[i], name, sizeof(name)) > 0 && !strcmp(name, "AppProxyProvider")) body(pids[i], NO);
    }
}
// On-demand may reconnect without an observable Disconnected sample. Require a
// new owned provider process before acknowledging a requested restart; -1 means several match.
static int providerPID(int exclude) {
    __block int found = 0;
    eachProvider(^(int pid, BOOL installed) { if (installed && pid != exclude) found = found ? -1 : pid; });
    return found;
}
// Replaces providers without a session stop. iOS treats a stop like the user turning the VPN off
// and lets the selected apps go direct until the next start; so does a provider ending its own
// session, which on-demand then reconnects. A killed provider's apps get no connection until
// iOS reports the session disconnected and on-demand starts a replacement.
static void endProviders(void) {
    eachProvider(^(int pid, BOOL installed) { (void)installed; kill(pid, SIGKILL); });
}
// Sends the connected provider a message and returns its reply, or nil without one.
static NSData *message(NSString *text, double seconds) {
    __block BOOL answered = NO;
    __block NSData *reply = nil;
    [NEAppProxyProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NEAppProxyProviderManager *> *managers, NSError *error) {
        NETunnelProviderSession *session = nil;
        for (NEAppProxyProviderManager *manager in error ? @[] : managers)
            if ([((NETunnelProviderProtocol *)manager.protocolConfiguration).providerBundleIdentifier isEqual:ProviderID]) session = (NETunnelProviderSession *)manager.connection;
        if (!session || session.status != NEVPNStatusConnected || ![session sendProviderMessage:[text dataUsingEncoding:NSUTF8StringEncoding] returnError:nil responseHandler:^(NSData *response) {
            reply = response;
            answered = YES;
        }]) answered = YES;
    }];
    // Framework callbacks arrive on the main queue, which this thread services here.
    double deadline = awakeSeconds() + seconds;
    while (!answered && awakeSeconds() < deadline) [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.02]];
    return reply;
}
// Starts the session and waits for a provider other than previousPID to connect. Start is
// repeated while iOS reports the session idle, so a stopped session is not left behind quietly.
static void startSession(NSUUID *uuid, int previousPID) {
    // A killed provider can take iOS 15 seconds to notice.
    double deadline = awakeSeconds() + 30, started = -10;
    while (awakeSeconds() < deadline) {
        int state = sessionStatus(uuid);
        if (state == SessionConnected && providerPID(previousPID) != 0) return;
        if (state <= SessionDisconnected && awakeSeconds() - started >= 2) { startCommand(uuid); started = awakeSeconds(); }
        usleep(100000);
    }
    fail("The settings were saved, but the tunnel did not connect. Retry or choose another proxy.");
}

static NSDictionary *status(void) {
    Owned o = owned();
    if (!o.config) return @{@"enabled": @NO, @"connected": @NO};
    return @{@"enabled": @(enabled(appProxy(o.config))), @"connected": @((BOOL)(sessionStatus(o.uuid) == SessionConnected))};
}
static NSDictionary *apply(NSDictionary *settings) {
    Owned o = owned();
    id config = o.config;
    NSUUID *uuid = o.uuid;
    BOOL created = !config;
    if (!created) appProxy(config);
    if (created) {
        Class cls = NSClassFromString(@"NEConfiguration");
        if (![cls instancesRespondToSelector:@selector(initWithName:grade:)]) fail("Configuration constructor is unavailable.");
        config = [[cls alloc] initWithName:@"Slipstream" grade:1];
        uuid = get(config, @"identifier");
        put(config, @"setName:", nameFor(uuid));
        put(config, @"setApplication:", AppID);
        put(config, @"setApplicationIdentifier:", AppID);
    }
    NSString *proxyURL = settings[@"proxy_url"];
    NETunnelProviderProtocol *protocol = [[NETunnelProviderProtocol alloc] initWithPluginType:AppID];
    protocol.providerBundleIdentifier = ProviderID;
    protocol.serverAddress = settings[@"proxy_ip"];
    protocol.providerConfiguration = @{SlipstreamProxyURLKey: proxyURL};
    protocol.disconnectOnSleep = NO;
    // An app proxy has no interface, addresses or routes. App rules alone choose the flows iOS
    // diverts to it.
    id vpn = [NSClassFromString(@"NEVPNApp") new];
    put(vpn, @"setProtocol:", protocol);
    number(vpn, @"setTunnelType:", AppProxyTunnel);
    NSMutableArray *rules = [NSMutableArray array];
    for (NSString *identifier in settings[@"bundle_ids"]) [rules addObject:[[NSClassFromString(@"NEAppRule") alloc] initWithSigningIdentifier:identifier]];
    put(vpn, @"setAppRules:", rules);
    number(vpn, @"setEnabled:", YES);
    put(vpn, @"setOnDemandRules:", @[[NEOnDemandRuleConnect new]]);
    number(vpn, @"setOnDemandEnabled:", YES);
    put(config, @"setAppVPN:", vpn);
    // Private setters can be ignored silently; read the result back.
    if (![get(config, @"identifier") isEqual:uuid] || ![get(config, @"name") isEqual:nameFor(uuid)]) fail("configuration identity mismatch; refusing operation");
    appProxy(config);
    if (created) {
        if (access(Journal, F_OK) == 0 && unlink(Journal)) fail("Could not replace the absent configuration's journal.");
        saveJournal(uuid);
    }
    // Zero when unknown: an orphaned or replaced provider must not block the change.
    int previousPID = MAX(providerPID(0), 0);
    __block BOOL replaced = NO;
    eachProvider(^(int pid, BOOL installed) { (void)pid; if (!installed) replaced = YES; });
    // Saving while connected leaves the session running.
    save(o.manager, config);
    if (!created) {
        // A provider from before an upgrade would keep running the replaced code.
        if (replaced) endProviders();
        else if (sessionStatus(uuid) != SessionConnected) previousPID = 0; // Any connected provider will do.
        // iOS answers only after applying the saved app rules; a rule per system app once took 11 s.
        else if (![message([SlipstreamReload stringByAppendingString:proxyURL], 15) isEqualToData:[SlipstreamReloaded dataUsingEncoding:NSUTF8StringEncoding]]) endProviders();
        else return @{};
    }
    startSession(uuid, previousPID);
    return @{};
}
static NSDictionary *removeOwned(void) {
    Owned o = owned();
    if (o.config) removeConfiguration(o.manager, o.config);
    if (unlink(Journal) && errno != ENOENT) fail("Could not remove the configuration journal.");
    return @{};
}
static NSDictionary *check(void) {
    NSData *reply = message(SlipstreamCheck, 10);
    NSDictionary *result = reply ? [NSJSONSerialization JSONObjectWithData:reply options:0 error:nil] : nil;
    if (![result isKindOfClass:NSDictionary.class]) fail("The provider returned no check result.");
    return result;
}

// Results go to Rust as malloc'd JSON, {"error": message} on failure. No configuration
// contents appear in errors.
static char *run(NSDictionary *(^body)(void)) { @autoreleasepool {
    NSDictionary *result;
    @try {
        if (geteuid() != 0) fail("Root access is required.");
        result = body();
    } @catch (NSException *exception) {
        result = @{@"error": [exception.name isEqual:@"Slipstream"] ? exception.reason : @"Network Extension operation failed. Retry after jailbreaking."};
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    return data ? strndup(data.bytes, data.length) : NULL;
} }
char *slipstream_tunnel_status(void) { return run(^{ return status(); }); }
char *slipstream_tunnel_remove(void) { return run(^{ return removeOwned(); }); }
char *slipstream_provider_check(void) { return run(^{ return check(); }); }
char *slipstream_tunnel_apply(const char *json) {
    return run(^{
        NSDictionary *settings = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:json length:strlen(json)] options:0 error:nil];
        if (![settings isKindOfClass:NSDictionary.class] || ![settings[@"proxy_url"] isKindOfClass:NSString.class] || ![settings[@"proxy_ip"] isKindOfClass:NSString.class] || ![settings[@"bundle_ids"] isKindOfClass:NSArray.class]) fail("invalid tunnel settings");
        return apply(settings);
    });
}

// The current path's network, without opening a connection: Wi-Fi, Cellular, or Network for
// anything else, such as another VPN.
char *slipstream_network(void) { @autoreleasepool {
    nw_path_monitor_t monitor = nw_path_monitor_create();
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block const char *label = NULL;
    __block BOOL handled = NO;
    nw_path_monitor_set_queue(monitor, dispatch_queue_create("local.slipstream.path", DISPATCH_QUEUE_SERIAL));
    nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
        if (handled) return;
        handled = YES;
        if (nw_path_get_status(path) == nw_path_status_satisfied) {
            nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
                nw_interface_type_t type = nw_interface_get_type(interface);
                if (!nw_path_uses_interface_type(path, type)) return true;
                label = type == nw_interface_type_wifi ? "Wi-Fi" : type == nw_interface_type_cellular ? "Cellular" : "Network";
                return false;
            });
        }
        dispatch_semaphore_signal(done);
    });
    nw_path_monitor_start(monitor);
    BOOL timeout = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0;
    nw_path_monitor_cancel(monitor);
    return !timeout && label ? strdup(label) : NULL;
} }
