// Print the network interface lists that apps' VPN checks read, as JSON: the scoped proxy
// settings keys, every interface name, and the default path's interfaces.
#include <CFNetwork/CFNetwork.h>
#include <Network/Network.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>

static void list(const char *key, void (^each)(void (^emit)(const char *name))) {
    __block const char *separator = "";
    printf("\"%s\":[", key);
    each(^(const char *name) { printf("%s\"%s\"", separator, name); separator = ","; });
    printf("]");
}

int main(void) {
    alarm(10);
    printf("{");
    list("scoped", ^(void (^emit)(const char *)) {
        CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
        CFDictionaryRef scoped = settings ? CFDictionaryGetValue(settings, CFSTR("__SCOPED__")) : NULL;
        CFIndex count = scoped && CFGetTypeID(scoped) == CFDictionaryGetTypeID() ? CFDictionaryGetCount(scoped) : 0;
        const void *keys[count > 0 ? count : 1];
        if (count) CFDictionaryGetKeysAndValues(scoped, keys, NULL);
        for (CFIndex i = 0; i < count; i++) {
            char name[IFNAMSIZ * 4];
            if (CFGetTypeID(keys[i]) == CFStringGetTypeID() && CFStringGetCString(keys[i], name, sizeof(name), kCFStringEncodingUTF8)) emit(name);
        }
        if (settings) CFRelease(settings);
    });
    printf(",");
    list("interfaces", ^(void (^emit)(const char *)) {
        struct if_nameindex *names = if_nameindex();
        for (struct if_nameindex *entry = names; entry && entry->if_name; entry++) emit(entry->if_name);
        if (names) if_freenameindex(names);
    });
    printf(",");
    list("path", ^(void (^emit)(const char *)) {
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        nw_path_monitor_t monitor = nw_path_monitor_create();
        nw_path_monitor_set_queue(monitor, dispatch_queue_create("interfaces", DISPATCH_QUEUE_SERIAL));
        nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
            nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) { emit(nw_interface_get_name(interface)); return true; });
            nw_path_monitor_cancel(monitor);
            dispatch_semaphore_signal(done);
        });
        nw_path_monitor_start(monitor);
        dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC));
    });
    printf("}\n");
    return 0;
}
