// Installed application names, isolated from the native tunnel configuration.
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <dlfcn.h>
#include <string.h>
@interface NSObject (SlipstreamAppEligibility)
- (id)initWithSigningIdentifier:(NSString *)identifier;
- (BOOL)signingIdentifierAllowed:(NSString *)identifier domainsOrAccountsRequired:(BOOL *)required;
@end
static id call(id object,NSString *selector) {
    SEL sel=NSSelectorFromString(selector);
    return [object respondsToSelector:sel] ? ((id(*)(id,SEL))objc_msgSend)(object,sel) : nil;
}
static BOOL hidden(id app) {
    id record=call(app,@"correspondingApplicationRecord");
    for(id object in @[app,record?:[NSNull null]]) {
        SEL prohibited=NSSelectorFromString(@"isLaunchProhibited");
        if([object respondsToSelector:prohibited]&&((BOOL(*)(id,SEL))objc_msgSend)(object,prohibited))return YES;
    }
    id url=call(app,@"bundleURL");
    NSDictionary *info=[url isKindOfClass:[NSURL class]]?[NSDictionary dictionaryWithContentsOfURL:[url URLByAppendingPathComponent:@"Info.plist"]]:nil;
    for(id tags in @[call(app,@"appTags")?:@[],call(record,@"appTags")?:@[],info[@"SBAppTags"]?:@[]]) {
        if(![tags isKindOfClass:[NSArray class]])continue;
        for(id tag in tags)if([tag isKindOfClass:[NSString class]]&&[tag rangeOfString:@"hidden" options:NSCaseInsensitiveSearch].location!=NSNotFound)return YES;
    }
    return NO;
}

char *slipstream_app_catalog(void) { @autoreleasepool { @try {
    dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices",RTLD_NOW);
    id workspace=call(NSClassFromString(@"LSApplicationWorkspace"),@"defaultWorkspace");
    NSArray *installed=call(workspace,@"allInstalledApplications");
    if(![installed isKindOfClass:NSArray.class] || !installed.count)return NULL;
    NSMutableArray *apps=[NSMutableArray array];
    for(id app in installed) {
        NSString *bundle=call(app,@"applicationIdentifier"), *name=call(app,@"localizedName");
        if(![bundle isKindOfClass:NSString.class] || !bundle.length)continue;
        id rule=[[NSClassFromString(@"NEAppRule") alloc]initWithSigningIdentifier:bundle];
        BOOL required=YES;
        BOOL allowed=[rule respondsToSelector:@selector(signingIdentifierAllowed:domainsOrAccountsRequired:)] && [rule signingIdentifierAllowed:bundle domainsOrAccountsRequired:&required];
        [apps addObject:@{@"id":bundle,@"name":name.length?name:bundle,@"hidden":@(hidden(app)),@"requires_all":@((BOOL)(required || !allowed))}];
    }
    NSData *json=[NSJSONSerialization dataWithJSONObject:apps options:0 error:nil];
    return json?strndup(json.bytes,json.length):NULL;
} @catch(NSException *exception){(void)exception;return NULL;} } }
