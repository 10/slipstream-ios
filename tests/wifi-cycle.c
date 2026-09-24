// MobileWiFi ABI references: see SOURCES.md. Experimental device-test helper.
#include <CoreFoundation/CoreFoundation.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static CFTypeRef (*Create)(CFAllocatorRef,int);
static int (*GetPower)(CFTypeRef);
static void (*SetPower)(CFTypeRef,int);
static CFArrayRef (*CopyDevices)(CFTypeRef);
static CFTypeRef (*CopyNetwork)(CFTypeRef);
static void (*Schedule)(CFTypeRef,CFRunLoopRef,CFStringRef);
static volatile sig_atomic_t interrupted;
static void interrupt_handler(int sig) { (void)sig; interrupted=1; }
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
static void run_for(double seconds) {
    double end=now()+seconds;
    while (!interrupted && now()<end) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.1,false);
        usleep(10000);
    }
}
static CFTypeRef manager(void) {
    void *h=dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi",RTLD_NOW);
    if (!h) { fprintf(stderr,"dlopen: %s\n",dlerror()); return NULL; }
#define LOAD(var,name) do { *(void **)(&var)=dlsym(h,name); if (!var) { fprintf(stderr,"Missing symbol: %s\n",name); return NULL; } } while(0)
    LOAD(Create,"WiFiManagerClientCreate"); LOAD(GetPower,"WiFiManagerClientGetPower");
    LOAD(SetPower,"WiFiManagerClientSetPower"); LOAD(CopyDevices,"WiFiManagerClientCopyDevices");
    LOAD(CopyNetwork,"WiFiDeviceClientCopyCurrentNetwork"); LOAD(Schedule,"WiFiManagerClientScheduleWithRunLoop");
    CFTypeRef m=Create(kCFAllocatorDefault,0);
    if (!m) { fprintf(stderr,"WiFiManagerClientCreate returned NULL\n"); return NULL; }
    Schedule(m,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode); run_for(0.2); return m;
}
static int status(CFTypeRef m,const char *label) {
    int power=GetPower(m),associated=0;
    CFArrayRef devices=CopyDevices(m); CFIndex count=devices?CFArrayGetCount(devices):0;
    for (CFIndex i=0;i<count;i++) {
        CFTypeRef network=CopyNetwork(CFArrayGetValueAtIndex(devices,i));
        if (network) { associated=1; CFRelease(network); }
    }
    if (devices) CFRelease(devices);
    printf("%s power=%d devices=%ld associated=%d",label,power,(long)count,associated);
    struct ifaddrs *all=NULL;
    if (!getifaddrs(&all)) {
        for (struct ifaddrs *a=all;a;a=a->ifa_next) {
            if (!a->ifa_addr || strcmp(a->ifa_name,"en0")) continue;
            if (a->ifa_addr->sa_family==AF_INET) {
                char ip[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET,&((struct sockaddr_in *)a->ifa_addr)->sin_addr,ip,sizeof ip)) printf(" en0_ipv4=%s",ip);
            }
        }
        freeifaddrs(all);
    }
    putchar('\n'); fflush(stdout); return associated;
}
static int number(const char *s,int minimum,int maximum) {
    char *end; errno=0; long n=strtol(s,&end,10);
    return (!errno && s[0] && !*end && n>=minimum && n<=maximum)?(int)n:-1;
}
static int restore(CFTypeRef m) {
    interrupted=0; SetPower(m,1); run_for(2);
    status(m,"restored"); return GetPower(m)==1?0:1;
}
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IOLBF,0);
    signal(SIGHUP,SIG_IGN); signal(SIGPIPE,SIG_IGN);
    signal(SIGINT,interrupt_handler); signal(SIGTERM,interrupt_handler);
    if (argc<2) { fprintf(stderr,"Usage: %s status | on | cycle SECONDS(1..60)\n",argv[0]); return 64; }
    bool cycle=!strcmp(argv[1],"cycle"),guard=!strcmp(argv[1],"--restore-after");
    int seconds=0,readyfd=-1;
    if (cycle || guard) {
        if (argc!=(guard?4:3) || (seconds=number(argv[2],1,guard?75:60))<0) return 64;
        if (guard && (readyfd=number(argv[3],3,1024))<0) return 64;
    } else if (argc!=2 || (strcmp(argv[1],"status") && strcmp(argv[1],"on"))) return 64;
    CFTypeRef m=manager(); if (!m) return 1;
    if (guard) {
        if (write(readyfd,"R",1)!=1) { close(readyfd); CFRelease(m); return 1; }
        close(readyfd); run_for(seconds); int rc=restore(m); CFRelease(m); return rc;
    }
    if (!strcmp(argv[1],"status")) {
        status(m,"status"); int p=GetPower(m); CFRelease(m); return (p==0 || p==1)?0:1;
    }
    if (!strcmp(argv[1],"on")) { int rc=restore(m); CFRelease(m); return rc; }
    status(m,"before");
    if (GetPower(m)!=1) { fprintf(stderr,"Refusing cycle: Wi-Fi is not on\n"); CFRelease(m); return 1; }
    char path[PATH_MAX],delay[16],fdarg[16]; uint32_t len=sizeof path;
    if (_NSGetExecutablePath(path,&len)) { CFRelease(m); return 1; }
    int fds[2]; if (pipe(fds)) { perror("pipe"); CFRelease(m); return 1; }
    snprintf(delay,sizeof delay,"%d",seconds+5); snprintf(fdarg,sizeof fdarg,"%d",fds[1]);
    pid_t child=fork();
    if (child==0) { close(fds[0]); setsid(); execl(path,path,"--restore-after",delay,fdarg,(char *)NULL); _exit(127); }
    close(fds[1]);
    if (child<0) { perror("fork"); close(fds[0]); CFRelease(m); return 1; }
    struct pollfd p={.fd=fds[0],.events=POLLIN}; char ready=0;
    int pollrc=poll(&p,1,10000);
    if (pollrc<=0 || read(fds[0],&ready,1)!=1 || ready!='R') {
        fprintf(stderr,"Restoration watchdog did not arm; Wi-Fi unchanged\n"); close(fds[0]); CFRelease(m); return 1;
    }
    close(fds[0]); if (interrupted) { CFRelease(m); return 1; } printf("watchdog_pid=%ld restore_deadline_seconds=%d\n",(long)child,seconds+5);
    SetPower(m,0); bool observed_off=false;
    for (int i=0;i<seconds && !interrupted;i++) { run_for(1); status(m,"off-window"); if (GetPower(m)==0) observed_off=true; }
    int rc=restore(m);
    bool associated=false;
    for (int i=0;i<20 && !interrupted;i++) { if ((associated=status(m,"reconnect"))) break; run_for(1); }
    printf("cycle_observed_power_off=%d\n",observed_off);
    CFRelease(m); return rc || !observed_off || !associated;
}
