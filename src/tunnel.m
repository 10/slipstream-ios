// Exact-owned Network Extension configuration and lifecycle. No packet routing here.
// NEConfiguration/NEVPNApp signatures: AirKeeper 9be334a6eaee8d086708ee4d89963d229a8684cf.
// Protocol initializer/application getters: nst/iOS-Runtime-Headers; runtime-checked.
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <objc/message.h>
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
// Earlier releases used a packet tunnel. Its configuration stays owned so that an upgrade can
// replace it and disable can remove it.
static NSString *const PacketProviderID = @"local.slipstream.app.packet";

@interface NSObject (ResearchPrivateAPI)
+ (id)sharedManagerForAllUsers;
- (id)initWithName:(NSString *)name grade:(NSInteger)grade;
- (id)initWithSigningIdentifier:(NSString *)identifier;
- (id)initWithPluginType:(NSString *)type;
- (BOOL)signingIdentifierAllowed:(NSString *)identifier domainsOrAccountsRequired:(BOOL *)required;
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
static void errorResult(NSError *error) {
    if (error) fail([[NSString stringWithFormat:@"Network Extension operation failed (%@ %ld).",error.domain,(long)error.code] UTF8String]);
}
// iOS can take several seconds to answer while it relaunches its Network Extension daemons,
// as under memory pressure; 6-10 s answers were measured on the XS.
static void waitFor(dispatch_semaphore_t done) {
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC))) fail("operation timeout; state uncertain, retain UUID journal");
}
static NSArray *load(id manager) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSArray *result = nil;
    __block NSError *failure = nil;
    [manager loadConfigurationsWithCompletionQueue:dispatch_get_global_queue(QOS_CLASS_UTILITY, 0) handler:^(NSArray *configs, NSError *error) { result = configs; failure = error; dispatch_semaphore_signal(done); }];
    waitFor(done); errorResult(failure);
    if (result && ![result isKindOfClass:NSArray.class]) fail("unexpected configuration collection");
    return result ?: @[];
}
static NSString *nameFor(NSUUID *uuid) { return [AppID stringByAppendingFormat:@".%@", uuid.UUIDString]; }
// Returns whether the configuration uses the current app proxy rather than the packet tunnel.
static BOOL checkOwned(id config, NSUUID *uuid) {
    if (![[get(config, @"identifier") UUIDString] isEqual:uuid.UUIDString] || ![get(config, @"name") isEqual:nameFor(uuid)]) fail("configuration identity mismatch; refusing operation");
    id appVPN=get(config,@"appVPN"),vpn=get(config,@"VPN");
    if((appVPN!=nil)==(vpn!=nil)) fail("ambiguous configuration type");
    id chosen=appVPN?:vpn;
    NETunnelProviderProtocol *protocol=get(chosen,@"protocol");
    if(!has(chosen,@"tunnelType"))fail("unexpected tunnel type");
    // Tunnel type 1 is a packet tunnel, 2 an app proxy.
    NSInteger type=((NSInteger(*)(id,SEL))objc_msgSend)(chosen,NSSelectorFromString(@"tunnelType"));
    if(appVPN && type==2 && [protocol.providerBundleIdentifier isEqual:ProviderID])return YES;
    if(type==1 && [protocol.providerBundleIdentifier isEqual:PacketProviderID])return NO;
    fail("provider mismatch");
}
// Deadlines count awake time: a sleeping phone pauses iOS and this process alike.
static double awakeSeconds(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW)/1e9; }
static int sessionStatus(NSUUID *uuid, int type) {
    unsigned char bytes[16];[uuid getUUIDBytes:bytes];void *session=ne_session_create(bytes,type);
    if(!session)fail("session unavailable");
    dispatch_semaphore_t done=dispatch_semaphore_create(0);__block int current=-1;
    ne_session_get_status(session,dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^(int value){current=value;dispatch_semaphore_signal(done);});
    waitFor(done);
    ne_session_release(session);return current;
}
static void startCommand(NSUUID *uuid, int type) {
    unsigned char bytes[16];[uuid getUUIDBytes:bytes];void *session=ne_session_create(bytes,type);
    if(!session)fail("session unavailable");
    ne_session_start_with_options(session,NULL);ne_session_send_barrier(session);ne_session_release(session);
}
static void saveJournal(NSUUID *uuid,const char *path){
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)fail("cannot create journal");
    NSData *data=[[uuid.UUIDString stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if(write(fd,data.bytes,data.length)!=(ssize_t)data.length||fsync(fd))fail("journal write failed");close(fd);
}
static NSUUID *readJournal(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) fail("cannot open UUID journal");
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != 0 || (info.st_mode & 077) || info.st_size != 37) fail("UUID journal must be a root-owned mode-600 regular file with one UUID");
    char text[38] = {0};
    ssize_t size = read(fd, text, 37); close(fd);
    if (size != 37 || text[36] != '\n') fail("invalid UUID journal");
    text[36] = 0;
    NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:text]];
    if (!uuid) fail("invalid UUID journal");
    return uuid;
}

static const char *Journal=SLIPSTREAM_PREFIX "/etc/slipstream/tunnel.uuid";
static BOOL enabled(id vpn) {
    NSString *selector=has(vpn,@"isEnabled")?@"isEnabled":@"enabled";
    if(!has(vpn,selector)) fail("VPN enabled state is unavailable.");
    return ((BOOL(*)(id,SEL))objc_msgSend)(vpn,NSSelectorFromString(selector));
}
static void removeConfiguration(id manager,id config) {
    dispatch_semaphore_t done=dispatch_semaphore_create(0); __block NSError *failure=nil;
    [manager removeConfiguration:config withCompletionQueue:dispatch_get_global_queue(QOS_CLASS_UTILITY,0) handler:^(NSError *error){failure=error;dispatch_semaphore_signal(done);}];
    waitFor(done); errorResult(failure);
}
static void save(id manager,id config) {
    dispatch_semaphore_t done=dispatch_semaphore_create(0); __block NSError *failure=nil;
    [manager saveConfiguration:config withCompletionQueue:dispatch_get_global_queue(QOS_CLASS_UTILITY,0) handler:^(NSError *error){failure=error;dispatch_semaphore_signal(done);}];
    waitFor(done); errorResult(failure);
}
// Calls body for each running provider, with whether it runs the installed executable. Others
// are from before an upgrade, including the earlier packet tunnel provider. An upgrade replaces
// the executable; providers started earlier no longer resolve their path, so those are matched
// by name.
static void eachProvider(void (^body)(int pid,BOOL installed)) {
    char executable[PATH_MAX],plugins[PATH_MAX];
    if(!realpath(SLIPSTREAM_PREFIX "/Applications/Slipstream.app/PlugIns/AppProxyProvider.appex/AppProxyProvider",executable) ||
       !realpath(SLIPSTREAM_PREFIX "/Applications/Slipstream.app/PlugIns",plugins))fail("The app proxy provider is not installed.");
    strlcat(plugins,"/",sizeof(plugins));
    int pids[8192],size=proc_listpids(1,0,pids,sizeof(pids));
    if(size<=0 || size>=(int)sizeof(pids))fail("Could not inspect the app proxy provider.");
    for(int i=0;i<size/(int)sizeof(int);i++) {
        char path[PATH_MAX],name[64];
        if(pids[i]<=0)continue;
        if(proc_pidpath(pids[i],path,sizeof(path))>0) {
            if(!strcmp(path,executable))body(pids[i],YES);
            else if(!strncmp(path,plugins,strlen(plugins)))body(pids[i],NO);
        }
        else if(proc_name(pids[i],name,sizeof(name))>0 && (!strcmp(name,"AppProxyProvider") || !strcmp(name,"PacketProvider")))body(pids[i],NO);
    }
}
// On-demand may reconnect without an observable Disconnected sample. Require a
// new owned provider process before acknowledging a requested restart; -1 means several match.
static int providerPID(int exclude) {
    __block int found=0;
    eachProvider(^(int pid,BOOL installed){ if(installed && pid!=exclude)found=found?-1:pid; });
    return found;
}
// Replaces providers without a session stop. iOS treats a stop like the user turning the VPN off
// and lets the selected apps go direct until the next start; so does a provider ending its own
// session, which on-demand then reconnects. A killed provider's apps get no connection until
// iOS reports the session disconnected and on-demand starts a replacement.
static void endProviders(void) {
    eachProvider(^(int pid,BOOL installed){ (void)installed; kill(pid,SIGKILL); });
}
// Asks the connected provider to switch proxies in place, keeping the session up. NO when no
// provider accepts, such as a provider from before an upgrade.
static BOOL reloadProvider(NSString *proxyURL) {
    __block BOOL answered=NO,reloaded=NO;
    NSData *message=[[@"reload\n" stringByAppendingString:proxyURL] dataUsingEncoding:NSUTF8StringEncoding];
    [NEAppProxyProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NEAppProxyProviderManager*> *managers,NSError *error) {
        NETunnelProviderSession *session=nil;
        for(NEAppProxyProviderManager *manager in error?@[]:managers)
            if([((NETunnelProviderProtocol*)manager.protocolConfiguration).providerBundleIdentifier isEqual:ProviderID])session=(NETunnelProviderSession*)manager.connection;
        if(!session || session.status!=NEVPNStatusConnected || ![session sendProviderMessage:message returnError:nil responseHandler:^(NSData *response) {
            reloaded=[response isEqualToData:[@"reloaded" dataUsingEncoding:NSUTF8StringEncoding]];answered=YES;
        }])answered=YES;
    }];
    // Framework callbacks arrive on the main queue, which this thread services here. They wait
    // while iOS applies the saved app rules, which took over 8 seconds for a rule per system app.
    double deadline=awakeSeconds()+15;
    while(!answered && awakeSeconds()<deadline)[NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.02]];
    return reloaded;
}
// Starts the session and waits for a provider other than previousPID to connect. Start is
// repeated while iOS reports the session idle, so a stopped session is not left behind quietly.
static void startSession(NSUUID *uuid,int type,int previousPID) {
    // A killed provider can take iOS 15 seconds to notice.
    double deadline=awakeSeconds()+30,started=-10;
    while(awakeSeconds()<deadline) {
        int state=sessionStatus(uuid,type);
        if(state==3 && providerPID(previousPID)!=0)return;
        if(state<=1 && awakeSeconds()-started>=2){startCommand(uuid,type);started=awakeSeconds();}
        usleep(100000);
    }
    fail("The settings were saved, but the tunnel did not connect. Retry or choose another proxy.");
}
static NSDictionary *operate(NSString *action,NSDictionary *settings) {
    Class managerClass=NSClassFromString(@"NEConfigurationManager");
    if(!has(managerClass,@"sharedManagerForAllUsers"))fail("Network Extension configuration is unavailable.");
    id manager=[managerClass sharedManagerForAllUsers];
    NSArray *configs=load(manager);
    NSUUID *uuid=access(Journal,F_OK)==0?readJournal(Journal):nil;
    id config=nil;
    BOOL current=NO;
    for(id candidate in configs) {
        if(uuid && [get(candidate,@"identifier") isEqual:uuid]) { current=checkOwned(candidate,uuid); config=candidate; }
        else if([get(candidate,@"name") hasPrefix:[AppID stringByAppendingString:@"."]]) fail("An unrecognized Slipstream configuration exists. Its UUID journal is required.");
    }
    int previousType=config?(get(config,@"appVPN")?2:1):0;
    if([action isEqual:@"status"]) {
        id vpn=config?(get(config,@"appVPN")?:get(config,@"VPN")):nil;
        return @{@"enabled":@((BOOL)(vpn && enabled(vpn))),@"status":@(config?sessionStatus(uuid,previousType):0)};
    }
    if([action isEqual:@"disable"]) {
        if(config)removeConfiguration(manager,config);
        if(unlink(Journal) && errno!=ENOENT)fail("Could not remove the configuration journal.");
        return @{};
    }
    if(![action isEqual:@"enable"] && ![action isEqual:@"restart"])fail("Unknown tunnel action.");
    // iOS never starts a per-app packet tunnel's session once its configuration becomes an app
    // proxy, so an earlier release's configuration is replaced by a new one, not changed.
    id legacy=current?nil:config;
    if(legacy) { config=nil; previousType=0; }
    BOOL created=!config;
    if(created) {
        Class cls=NSClassFromString(@"NEConfiguration");
        if(![cls instancesRespondToSelector:@selector(initWithName:grade:)])fail("Configuration constructor is unavailable.");
        config=[[cls alloc]initWithName:@"Slipstream" grade:1];
        uuid=get(config,@"identifier");
        put(config,@"setName:",nameFor(uuid));
        put(config,@"setApplication:",AppID);
        put(config,@"setApplicationIdentifier:",AppID);
    }
    NETunnelProviderProtocol *protocol=[[NETunnelProviderProtocol alloc]initWithPluginType:AppID];
    protocol.providerBundleIdentifier=ProviderID;
    protocol.serverAddress=settings[@"proxy_ip"];
    protocol.providerConfiguration=@{@"proxy_url":settings[@"proxy_url"],@"proxy_ip":settings[@"proxy_ip"]};
    protocol.disconnectOnSleep=NO;
    // An app proxy has no interface, addresses or routes. App rules alone choose the flows iOS
    // diverts to it; for All apps, the caller lists every app the user installed.
    id vpn=[NSClassFromString(@"NEVPNApp") new];
    put(vpn,@"setProtocol:",protocol);
    number(vpn,@"setTunnelType:",2);
    NSMutableArray *rules=[NSMutableArray array];
    for(NSString *identifier in settings[@"bundle_ids"]) {
        id rule=[[NSClassFromString(@"NEAppRule") alloc]initWithSigningIdentifier:identifier];
        BOOL required=YES;
        if(!has(rule,@"signingIdentifierAllowed:domainsOrAccountsRequired:") || ![rule signingIdentifierAllowed:identifier domainsOrAccountsRequired:&required])fail("A selected app cannot use native per-app routing.");
        if(required)fail("A selected app requires a domain rule, which Slipstream cannot protect.");
        [rules addObject:rule];
    }
    put(vpn,@"setAppRules:",rules);
    number(vpn,@"setEnabled:",YES);
    put(vpn,@"setOnDemandRules:",@[[NEOnDemandRuleConnect new]]);
    number(vpn,@"setOnDemandEnabled:",YES);
    put(config,@"setAppVPN:",vpn);
    put(config,@"setVPN:",nil);
    if(!checkOwned(config,uuid))fail("provider mismatch");
    if(created) {
        // The earlier configuration goes only once its replacement is ready. Its provider is
        // killed first rather than stopped by the removal.
        if(legacy) { endProviders(); removeConfiguration(manager,legacy); }
        if(access(Journal,F_OK)==0 && unlink(Journal))fail("Could not replace the absent configuration's journal.");
        saveJournal(uuid,Journal);
    }
    // Zero when unknown: an orphaned or replaced provider must not block the change.
    int previousPID=MAX(providerPID(0),0);
    __block BOOL replaced=NO;
    eachProvider(^(int pid,BOOL installed){ (void)pid; if(!installed)replaced=YES; });
    // Session type 2 is a per-app VPN.
    int type=2;
    if(previousType==type) {
        // Saving while connected leaves the session running; the provider then switches proxies.
        save(manager,config);
        // A provider from before an upgrade would keep running the replaced code.
        if(replaced)endProviders();
        else if(sessionStatus(uuid,type)!=3)previousPID=0; // Any connected provider will do.
        else if(!reloadProvider(settings[@"proxy_url"]))endProviders();
        else return @{};
    } else save(manager,config);
    startSession(uuid,type,previousPID);
    return @{};
}
// Result ownership passes to Rust. No configuration contents appear in errors.
char *slipstream_tunnel(const char *action,const char *json) { @autoreleasepool {
    NSDictionary *result;
    @try {
        if(geteuid()!=0)fail("Root access is required.");
        NSData *data=json?[NSData dataWithBytes:json length:strlen(json)]:nil;
        NSDictionary *settings=data?[NSJSONSerialization JSONObjectWithData:data options:0 error:nil]:nil;
        result=operate([NSString stringWithUTF8String:action],settings);
    } @catch(NSException *exception) {
        result=@{@"error":[exception.name isEqual:@"Slipstream"]?exception.reason:@"Network Extension operation failed. Retry after jailbreaking."};
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    return data?strndup(data.bytes,data.length):NULL;
} }

// Report the current path label without opening a connection. A VPN may be
// represented by its virtual interface; callers label that simply Network.
char *slipstream_interface(void) { @autoreleasepool {
    nw_path_monitor_t monitor=nw_path_monitor_create();
    dispatch_semaphore_t done=dispatch_semaphore_create(0);
    __block NSString *name=nil; __block BOOL handled=NO;
    nw_path_monitor_set_queue(monitor,dispatch_queue_create("local.slipstream.path",DISPATCH_QUEUE_SERIAL));
    nw_path_monitor_set_update_handler(monitor,^(nw_path_t path){
        if(handled)return; handled=YES;
        if(nw_path_get_status(path)==nw_path_status_satisfied) {
            nw_path_enumerate_interfaces(path,^bool(nw_interface_t interface){
                nw_interface_type_t type=nw_interface_get_type(interface);
                if(nw_path_uses_interface_type(path,type)) {
                    name=[NSString stringWithUTF8String:nw_interface_get_name(interface)]; return false;
                }
                return true;
            });
        }
        dispatch_semaphore_signal(done);
    });
    nw_path_monitor_start(monitor);
    BOOL timeout=dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))!=0;
    nw_path_monitor_cancel(monitor);
    return !timeout && name?strdup(name.UTF8String):NULL;
} }
