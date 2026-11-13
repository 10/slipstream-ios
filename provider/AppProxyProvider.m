// The system diverts the selected apps' flows here by app rule; unlike a packet tunnel, this
// creates no network interface. Each flow reaches the Rust engine through a Unix socket pair.
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#import "ProviderInterface.h"

// src/engine.rs
extern int proxy_engine_start(const char *);
extern void proxy_engine_stop(void);
extern void proxy_engine_set_interface(unsigned);
extern int proxy_engine_tcp(int, const char *, unsigned short);
extern int proxy_engine_udp(int, unsigned short);
extern size_t proxy_engine_check(uint8_t *, size_t);

// Further flows are closed rather than queued.
static const NSUInteger MaxFlows=128;
// A UDP frame, as src/engine.rs reads it: the remote endpoint as a SOCKS5 address (at most 259
// bytes), then the datagram.
static const size_t MaxFrame=259+65535;

static NSError *posixError(int code) { return [NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:nil]; }

// Returns the provider's nonblocking end of a socket pair and stores the engine's end.
static int socketPair(int type,int size,int *engine) {
    int pair[2],one=1;
    if (socketpair(AF_UNIX,type,0,pair)) return -1;
    for (int i=0; i<2; i++) {
        setsockopt(pair[i],SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
        setsockopt(pair[i],SOL_SOCKET,SO_SNDBUF,&size,sizeof(size));
        setsockopt(pair[i],SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));
    }
    if (fcntl(pair[0],F_SETFL,O_NONBLOCK)<0) { close(pair[0]); close(pair[1]); return -1; }
    *engine=pair[1];
    return pair[0];
}

static NSData *encodeFrame(NWEndpoint *endpoint,NSData *datagram) {
    if (![endpoint isKindOfClass:NWHostEndpoint.class]) return nil;
    const char *name=((NWHostEndpoint*)endpoint).hostname.UTF8String;
    int port=((NWHostEndpoint*)endpoint).port.intValue;
    if (!name || port<=0 || port>65535) return nil;
    NSMutableData *frame=[NSMutableData dataWithCapacity:datagram.length+262];
    unsigned char address[16];
    if (inet_pton(AF_INET,name,address)==1) { [frame appendBytes:"\x01" length:1]; [frame appendBytes:address length:4]; }
    else if (inet_pton(AF_INET6,name,address)==1) { [frame appendBytes:"\x04" length:1]; [frame appendBytes:address length:16]; }
    else {
        size_t length=strlen(name);
        if (!length || length>255) return nil;
        unsigned char head[2]={3,(unsigned char)length};
        [frame appendBytes:head length:2]; [frame appendBytes:name length:length];
    }
    unsigned char bigEndian[2]={(unsigned char)(port>>8),(unsigned char)port};
    [frame appendBytes:bigEndian length:2];
    [frame appendData:datagram];
    return frame;
}

static NSData *decodeFrame(const unsigned char *frame,size_t length,NWHostEndpoint **endpoint) {
    char name[256];
    size_t used;
    if (length<1) return nil;
    if (frame[0]==1 && length>=7) { inet_ntop(AF_INET,frame+1,name,sizeof(name)); used=5; }
    else if (frame[0]==4 && length>=19) { inet_ntop(AF_INET6,frame+1,name,sizeof(name)); used=17; }
    else if (frame[0]==3 && length>=2 && length>=4+(size_t)frame[1]) { memcpy(name,frame+2,frame[1]); name[frame[1]]=0; used=2+frame[1]; }
    else return nil;
    unsigned port=(unsigned)frame[used]<<8 | frame[used+1];
    used+=2;
    // A relayed domain name need not be valid UTF-8.
    NSString *host=[NSString stringWithUTF8String:name];
    if (!host) return nil;
    *endpoint=[NWHostEndpoint endpointWithHostname:host port:[NSString stringWithFormat:@"%u",port]];
    return [NSData dataWithBytes:frame+used length:length-used];
}

// One captured flow and its engine session. State changes on the relay's serial queue.
@interface Relay : NSObject {
@protected
    int _fd;
    dispatch_queue_t _queue;
    dispatch_source_t _readable,_writable;
    BOOL _readPaused,_writePaused,_readClosed,_writeClosed,_finished;
}
@property (readonly) NEAppProxyFlow *flow;
@property (copy) void (^done)(void);
+ (int)socketType;
+ (int)bufferSize;
- (void)start;
- (void)readable;
- (void)writable;
@end

@implementation Relay
- (instancetype)initWithFlow:(NEAppProxyFlow*)flow fd:(int)fd {
    if ((self=[super init])) {
        _flow=flow;
        _fd=fd;
        _queue=dispatch_queue_create("local.slipstream.flow",DISPATCH_QUEUE_SERIAL);
        // Sources start suspended. The descriptor closes once both are cancelled.
        dispatch_group_t sources=dispatch_group_create();
        __weak Relay *weak=self;
        _readable=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)fd,0,_queue);
        _writable=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,(uintptr_t)fd,0,_queue);
        _readPaused=_writePaused=YES;
        dispatch_source_set_event_handler(_readable, ^{ Relay *owner=weak; if (owner && !owner->_finished) [owner readable]; });
        dispatch_source_set_event_handler(_writable, ^{ Relay *owner=weak; if (owner && !owner->_finished) [owner writable]; });
        for (dispatch_source_t source in @[_readable,_writable]) {
            dispatch_group_enter(sources);
            dispatch_source_set_cancel_handler(source, ^{ dispatch_group_leave(sources); });
        }
        dispatch_group_notify(sources,_queue, ^{ close(fd); });
    }
    return self;
}
+ (int)socketType { return SOCK_STREAM; }
+ (int)bufferSize { return 65536; }
- (void)start {}
- (void)readable {}
- (void)writable {}
- (void)pauseReading { if (!_readPaused) { _readPaused=YES; dispatch_suspend(_readable); } }
- (void)resumeReading { if (_readPaused && !_finished) { _readPaused=NO; dispatch_resume(_readable); } }
- (void)pauseWriting { if (!_writePaused) { _writePaused=YES; dispatch_suspend(_writable); } }
- (void)resumeWriting { if (_writePaused && !_finished) { _writePaused=NO; dispatch_resume(_writable); } }
- (void)closeRead:(NSError*)error { if (!_readClosed) { _readClosed=YES; [_flow closeReadWithError:error]; } }
- (void)closeWrite:(NSError*)error { if (!_writeClosed) { _writeClosed=YES; [_flow closeWriteWithError:error]; } }
// Runs on the queue. Closes whatever remains of the flow and releases the engine's socket.
- (void)finish:(NSError*)error {
    if (_finished) return;
    _finished=YES;
    [self closeRead:error];
    [self closeWrite:error];
    // A suspended source only completes its cancellation once resumed.
    if (_readPaused) dispatch_resume(_readable);
    if (_writePaused) dispatch_resume(_writable);
    dispatch_source_cancel(_readable);
    dispatch_source_cancel(_writable);
    void (^done)(void)=self.done;
    self.done=nil;
    if (done) done();
}
- (void)abort { dispatch_async(_queue, ^{ [self finish:posixError(ECONNABORTED)]; }); }
@end

// The engine answers with one status byte before relaying: 0 once the proxy has connected.
// The flow opens only then, so a refused destination fails the app's connect.
@interface TCPRelay : Relay
@end
@implementation TCPRelay {
    BOOL _connected;
    NSData *_pending;
    NSUInteger _offset;
}
- (void)start { dispatch_async(_queue, ^{ [self resumeReading]; }); }
- (void)opened:(NSError*)error {
    if (_finished) return;
    if (error) { [self finish:error]; return; }
    [self resumeReading];
    [self readFlow];
}
- (void)readable {
    if (!_connected) {
        unsigned char status=1;
        ssize_t n=recv(_fd,&status,1,0);
        if (n<0 && (errno==EAGAIN || errno==EINTR)) return;
        if (n!=1 || status!=0) { [self finish:posixError(ECONNREFUSED)]; return; }
        _connected=YES;
        [self pauseReading];
        [self.flow openWithLocalEndpoint:nil completionHandler:^(NSError *error) {
            dispatch_async(self->_queue, ^{ [self opened:error]; });
        }];
        return;
    }
    NSMutableData *data=[NSMutableData dataWithLength:65536];
    ssize_t n=recv(_fd,data.mutableBytes,data.length,0);
    if (n<0 && (errno==EAGAIN || errno==EINTR)) return;
    if (n<0) { [self finish:posixError(ECONNABORTED)]; return; }
    [self pauseReading];
    if (n==0) {
        [self closeWrite:nil];
        if (_readClosed) [self finish:nil];
        return;
    }
    data.length=(NSUInteger)n;
    [(NEAppProxyTCPFlow*)self.flow writeData:data withCompletionHandler:^(NSError *error) {
        dispatch_async(self->_queue, ^{
            if (self->_finished) return;
            if (error) [self finish:error];
            else [self resumeReading];
        });
    }];
}
- (void)readFlow {
    [(NEAppProxyTCPFlow*)self.flow readDataWithCompletionHandler:^(NSData *data,NSError *error) {
        dispatch_async(self->_queue, ^{
            if (self->_finished) return;
            if (error) { [self finish:error]; return; }
            if (!data.length) {
                shutdown(self->_fd,SHUT_WR);
                [self closeRead:nil];
                if (self->_writeClosed) [self finish:nil];
                return;
            }
            self->_pending=data;
            self->_offset=0;
            [self writable];
        });
    }];
}
// Writes the pending flow data to the engine, waiting for space as needed.
- (void)writable {
    [self pauseWriting];
    while (_offset<_pending.length) {
        ssize_t n=send(_fd,(const char*)_pending.bytes+_offset,_pending.length-_offset,0);
        if (n>0) { _offset+=(NSUInteger)n; continue; }
        if (n<0 && errno==EINTR) continue;
        if (n<0 && errno==EAGAIN) { [self resumeWriting]; return; }
        [self finish:posixError(ECONNABORTED)];
        return;
    }
    _pending=nil;
    [self readFlow];
}
@end

// Datagrams travel as engine frames that carry their remote endpoint.
@interface UDPRelay : Relay
@end
@implementation UDPRelay
+ (int)socketType { return SOCK_DGRAM; }
+ (int)bufferSize { return 262144; }
- (void)start {
    [self.flow openWithLocalEndpoint:nil completionHandler:^(NSError *error) {
        dispatch_async(self->_queue, ^{
            if (self->_finished) return;
            if (error) { [self finish:error]; return; }
            [self resumeReading];
            [self readFlow];
        });
    }];
}
- (void)readFlow {
    [(NEAppProxyUDPFlow*)self.flow readDatagramsWithCompletionHandler:^(NSArray<NSData*> *datagrams,NSArray<NWEndpoint*> *endpoints,NSError *error) {
        dispatch_async(self->_queue, ^{
            if (self->_finished) return;
            // No datagrams without an error: the app closed its socket.
            if (error || !datagrams.count) { [self finish:error]; return; }
            for (NSUInteger i=0; i<datagrams.count && i<endpoints.count; i++) {
                NSData *frame=encodeFrame(endpoints[i],datagrams[i]);
                // A full engine queue drops the datagram, as the network may.
                if (frame && send(self->_fd,frame.bytes,frame.length,0)<0 && errno!=EAGAIN && errno!=ENOBUFS) {
                    [self finish:posixError(ECONNABORTED)]; return;
                }
            }
            [self readFlow];
        });
    }];
}
- (void)readable {
    NSMutableData *frame=[NSMutableData dataWithLength:MaxFrame];
    ssize_t n=recv(_fd,frame.mutableBytes,frame.length,0);
    if (n<0 && (errno==EAGAIN || errno==EINTR)) return;
    // The engine ended the session, for example after the proxy changed.
    if (n<=0) { [self finish:posixError(ECONNABORTED)]; return; }
    NWHostEndpoint *endpoint=nil;
    NSData *datagram=decodeFrame(frame.bytes,(size_t)n,&endpoint);
    if (!datagram) return;
    [self pauseReading];
    [(NEAppProxyUDPFlow*)self.flow writeDatagrams:@[datagram] sentByEndpoints:@[endpoint] completionHandler:^(NSError *error) {
        dispatch_async(self->_queue, ^{
            if (self->_finished) return;
            if (error) [self finish:error];
            else [self resumeReading];
        });
    }];
}
@end

@interface AppProxyProvider : NEAppProxyProvider
@property BOOL stopped;
@property NSMutableSet<Relay*> *relays;
@property nw_path_monitor_t monitor;
@end

@implementation AppProxyProvider
- (instancetype)init {
    if ((self=[super init])) {
        _relays=[NSMutableSet set];
        _stopped=YES;
        // A write to a socket whose peer has closed must fail with EPIPE, not end the provider.
        signal(SIGPIPE,SIG_IGN);
    }
    return self;
}
// Hands a new flow to the engine through a socket pair. NO closes the flow; it never goes direct.
- (BOOL)accept:(NEAppProxyFlow*)flow relay:(Class)kind start:(int(^)(int engineFD))start {
    Relay *relay;
    @synchronized (self) {
        if (self.stopped || self.relays.count>=MaxFlows) return NO;
        int engineFD,fd=socketPair([kind socketType],[kind bufferSize],&engineFD);
        if (fd<0) return NO;
        // The engine owns its end even when it refuses the flow.
        if (start(engineFD)) { close(fd); return NO; }
        relay=[[kind alloc]initWithFlow:flow fd:fd];
        __weak AppProxyProvider *weak=self;
        __weak Relay *weakRelay=relay;
        relay.done=^{
            AppProxyProvider *owner=weak;
            Relay *finished=weakRelay;
            if (owner && finished) { @synchronized (owner) { [owner.relays removeObject:finished]; } }
        };
        [self.relays addObject:relay];
    }
    [relay start];
    return YES;
}
- (BOOL)handleNewFlow:(NEAppProxyFlow*)flow {
    if (![flow isKindOfClass:NEAppProxyTCPFlow.class]) return NO;
    NWEndpoint *remote=((NEAppProxyTCPFlow*)flow).remoteEndpoint;
    if (![remote isKindOfClass:NWHostEndpoint.class]) return NO;
    NSString *host=((NWHostEndpoint*)remote).hostname;
    int port=((NWHostEndpoint*)remote).port.intValue;
    if (!host.length || port<=0 || port>65535) return NO;
    return [self accept:flow relay:TCPRelay.class start:^int(int engineFD) {
        return proxy_engine_tcp(engineFD,host.UTF8String,(unsigned short)port);
    }];
}
// The engine decides by the first datagram's port whether the proxy can carry the flow.
- (BOOL)acceptUDP:(NEAppProxyUDPFlow*)flow port:(int)port {
    return [self accept:flow relay:UDPRelay.class start:^int(int engineFD) {
        return proxy_engine_udp(engineFD,(unsigned short)(port>0 && port<=65535 ? port : 0));
    }];
}
- (BOOL)handleNewUDPFlow:(NEAppProxyUDPFlow*)flow initialRemoteEndpoint:(NWEndpoint*)remote {
    return [self acceptUDP:flow port:[remote isKindOfClass:NWHostEndpoint.class] ? ((NWHostEndpoint*)remote).port.intValue : 0];
}
// iOS 18 replaces the method above with this one.
- (BOOL)handleNewUDPFlow:(NEAppProxyUDPFlow*)flow initialRemoteFlowEndpoint:(nw_endpoint_t)remote API_AVAILABLE(ios(18.0)) {
    return [self acceptUDP:flow port:nw_endpoint_get_port(remote)];
}
// Removes every current flow; the caller aborts them outside the lock.
- (NSArray<Relay*>*)takeRelays {
    NSArray *relays=self.relays.allObjects;
    [self.relays removeAllObjects];
    return relays;
}
- (void)startProxyWithOptions:(NSDictionary*)options completionHandler:(void(^)(NSError*))completion {
    (void)options;
    NETunnelProviderProtocol *protocol=(NETunnelProviderProtocol*)self.protocolConfiguration;
    NSString *proxy=protocol.providerConfiguration[SlipstreamProxyURLKey], *address=protocol.serverAddress;
    if (![proxy isKindOfClass:NSString.class] || !address.length) { completion(posixError(EINVAL)); return; }
    if (proxy_engine_start(proxy.UTF8String)) { completion(posixError(EIO)); return; }
    @synchronized (self) { self.stopped=NO; }
    // Upstream sockets bind to the physical underlay, never another VPN's tunnel. Index zero
    // blocks connects until a physical path is available.
    proxy_engine_set_interface(0);
    dispatch_queue_t queue=dispatch_queue_create("local.slipstream.path",DISPATCH_QUEUE_SERIAL);
    __weak AppProxyProvider *weak=self;
    // Flows arrive once start completes; give them an interface when one is available.
    __block BOOL settled=NO;
    void (^ready)(void)=^{ if (!settled) { settled=YES; [weak applySettings:address completion:completion]; } };
    self.monitor=nw_path_monitor_create();
    nw_path_monitor_prohibit_interface_type(self.monitor,nw_interface_type_other);
    nw_path_monitor_prohibit_interface_type(self.monitor,nw_interface_type_loopback);
    nw_path_monitor_set_queue(self.monitor,queue);
    nw_path_monitor_set_update_handler(self.monitor, ^(nw_path_t path) {
        AppProxyProvider *owner=weak;
        if (!owner || owner.stopped) return;
        __block unsigned index=0;
        nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
            nw_interface_type_t type=nw_interface_get_type(interface);
            if (nw_path_uses_interface_type(path,type) && (type==nw_interface_type_wifi || type==nw_interface_type_cellular || type==nw_interface_type_wired)) {
                index=nw_interface_get_index(interface); return false;
            }
            return true;
        });
        proxy_engine_set_interface(index);
        ready();
    });
    nw_path_monitor_start(self.monitor);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),queue,ready);
}
// DNS for the selected apps goes to the proxied resolver. No proxy settings are published and
// no addresses or routes are claimed.
- (void)applySettings:(NSString*)address completion:(void(^)(NSError*))completion {
    NETunnelNetworkSettings *settings=[[NETunnelNetworkSettings alloc]initWithTunnelRemoteAddress:address];
    settings.DNSSettings=[[NEDNSSettings alloc]initWithServers:@[@"8.8.8.8"]];
    settings.DNSSettings.matchDomains=@[@""];
    [self setTunnelNetworkSettings:settings completionHandler:^(NSError *error) { completion(error); }];
}
- (void)handleAppMessage:(NSData*)message completionHandler:(void(^)(NSData*))completion {
    if (!completion) return;
    NSString *text=[[NSString alloc]initWithData:message encoding:NSUTF8StringEncoding];
    // Switches proxies in place: the session stays up and current flows reconnect through
    // the new proxy.
    if ([text hasPrefix:SlipstreamReload] && text.length>SlipstreamReload.length) {
        NSString *proxy=[text substringFromIndex:SlipstreamReload.length];
        NSArray<Relay*> *relays=nil;
        @synchronized (self) {
            if (!self.stopped && !proxy_engine_start(proxy.UTF8String)) relays=[self takeRelays];
        }
        for (Relay *relay in relays) [relay abort];
        completion(relays?[SlipstreamReloaded dataUsingEncoding:NSUTF8StringEncoding]:nil);
        return;
    }
    if (![text isEqualToString:SlipstreamCheck]) { completion(nil); return; }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        uint8_t result[256];
        size_t length=proxy_engine_check(result,sizeof(result));
        completion(length?[NSData dataWithBytes:result length:length]:nil);
    });
}
- (void)stopProxyWithReason:(NEProviderStopReason)reason completionHandler:(void(^)(void))completion {
    (void)reason;
    NSArray<Relay*> *relays;
    @synchronized (self) { self.stopped=YES; relays=[self takeRelays]; }
    for (Relay *relay in relays) [relay abort];
    if (self.monitor) { nw_path_monitor_cancel(self.monitor); self.monitor=nil; }
    proxy_engine_stop();
    completion();
}
@end
