#include "Bridge.h"
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

// Swift weak-links its concurrency runtime below iOS 15, and iOS 14 jailbreaks only trust
// strong launch dependencies. This reference keeps the bundled fallback a strong dependency.
extern void *swift_task_getCurrent(void);
void *(*const slipstream_concurrency_runtime)(void) = swift_task_getCurrent;

static char *failure(void) {
    return strdup("{\"ok\":false,\"message\":\"Could not reach the Slipstream service. Retry after jailbreaking or reinstalling the app.\"}");
}
char *slipstream_request(const char *request) {
    int input[2], output[2];
    if (pipe(input)) return failure();
    if (pipe(output)) {close(input[0]);close(input[1]);return failure();}
    fcntl(input[1],F_SETNOSIGPIPE,1);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions,input[0],STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions,output[1],STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);
    for (int i=0;i<2;i++) {posix_spawn_file_actions_addclose(&actions,input[i]);posix_spawn_file_actions_addclose(&actions,output[i]);}
    char *args[]={"slipstream-helper",NULL};
    char *env[]={"PATH=/usr/bin:/bin",NULL};
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes,POSIX_SPAWN_CLOEXEC_DEFAULT);
    pid_t child;
    int error=posix_spawn(&child,SLIPSTREAM_PREFIX "/Applications/Slipstream.app/slipstream-helper",&actions,&attributes,args,env);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    close(input[0]);close(output[1]);
    if (error) {close(input[1]);close(output[0]);return failure();}
    size_t sent=0, len=strlen(request);
    while (sent<len) {
        ssize_t n=write(input[1],request+sent,len-sent);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) break;
        sent+=(size_t)n;
    }
    close(input[1]);
    size_t used=0, capacity=2*1024*1024;
    char *buffer=malloc(capacity+1);
    if (!buffer) {close(output[0]);return failure();}
    time_t deadline=time(NULL)+65;
    int valid=0;
    while (time(NULL)<deadline && used<capacity) {
        struct pollfd p={.fd=output[0],.events=POLLIN};
        int ready=poll(&p,1,500);
        if (ready<0 && errno!=EINTR) break;
        if (ready<=0) continue;
        ssize_t n=read(output[0],buffer+used,capacity-used);
        if (n==0) {valid=1;break;}
        if (n<0) {if(errno==EINTR)continue;break;}
        used+=(size_t)n;
    }
    close(output[0]);
    // The root helper has its own alarm; never block the UI queue on child reaping.
    while (waitpid(child,NULL,valid ? 0 : WNOHANG)<0 && errno==EINTR) {}
    if (!valid || !used) {free(buffer);return failure();}
    buffer[used]=0;
    return buffer;
}
