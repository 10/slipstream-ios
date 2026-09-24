// Public provider messaging needs the containing app's bundle identity. This
// runs in the existing authenticated helper inside Slipstream.app.
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#include <stdio.h>
#include <unistd.h>
int slipstream_provider_latency(void) { @autoreleasepool {
    alarm(12);
    dispatch_semaphore_t done=dispatch_semaphore_create(0);
    __block unsigned long long milliseconds=0;
    __block NSString *udp=nil;
    [NEAppProxyProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NEAppProxyProviderManager*> *managers,NSError *error) {
        if(error){dispatch_semaphore_signal(done);return;}
        NETunnelProviderSession *session=nil;
        for(NETunnelProviderManager *manager in managers) {
            NETunnelProviderProtocol *protocol=(id)manager.protocolConfiguration;
            if([protocol.providerBundleIdentifier isEqual:@"local.slipstream.app.proxy"] && manager.enabled) {
                if(session){dispatch_semaphore_signal(done);return;}
                session=(NETunnelProviderSession*)manager.connection;
            }
        }
        if(!session || session.status!=NEVPNStatusConnected){dispatch_semaphore_signal(done);return;}
        NSError *sendError=nil;
        BOOL sent=[session sendProviderMessage:[@"latency" dataUsingEncoding:NSUTF8StringEncoding] returnError:&sendError responseHandler:^(NSData *response) {
            if(response.length>0 && response.length<40) {
                NSString *text=[[NSString alloc]initWithData:response encoding:NSUTF8StringEncoding];
                NSScanner *scanner=text?[NSScanner scannerWithString:text]:nil;
                unsigned long long value=0;
                NSString *word=nil;
                if([scanner scanUnsignedLongLong:&value] && value>0) {
                    [scanner scanCharactersFromSet:NSCharacterSet.letterCharacterSet intoString:&word];
                    if(scanner.isAtEnd) {
                        milliseconds=value;
                        if([@[@"relayed",@"unsupported",@"blocked"] containsObject:word?:@""])udp=word;
                    }
                }
            }
            dispatch_semaphore_signal(done);
        }];
        if(!sent || sendError)dispatch_semaphore_signal(done);
    }];
    NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:10];
    BOOL finished=NO;
    while(!finished && [deadline timeIntervalSinceNow]>0) {
        finished=dispatch_semaphore_wait(done,DISPATCH_TIME_NOW)==0;
        if(!finished)[NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.02]];
    }
    if(!finished || !milliseconds)return 1;
    if(udp)printf("%llu %s\n",milliseconds,udp.UTF8String);
    else printf("%llu\n",milliseconds);
    return 0;
} }
