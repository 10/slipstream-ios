// Narrow setuid launcher. The UI stays mobile; only the typed manager runs root.
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <grp.h>
extern char **environ;
extern int proc_pidpath(int, void *, uint32_t);

static void deny(void) {
    puts("{\"ok\":false,\"message\":\"Open Slipstream from the Home Screen to manage protection.\"}");
    exit(1);
}
extern int slipstream_provider_latency(void);
int main(int argc, char **argv) {
    uid_t caller=getuid();
    if (geteuid()!=0) deny();
    if (caller!=0) {
        char actual[PATH_MAX], resolved[PATH_MAX], expected[PATH_MAX];
        struct stat info;
        if (caller!=501 || proc_pidpath(getppid(),actual,sizeof(actual))<=0 ||
            !realpath(actual,resolved) || !realpath(SLIPSTREAM_PREFIX "/Applications/Slipstream.app/Slipstream",expected) ||
            strcmp(resolved,expected) || stat(expected,&info) || info.st_uid!=0 || (info.st_mode&022)) deny();
    }
    if (setgroups(0,NULL) || setgid(0) || setuid(0)) deny();
    chdir("/");
    umask(077);
    char *env[]={"PATH=" SLIPSTREAM_PREFIX "/usr/local/bin:" SLIPSTREAM_PREFIX "/usr/bin:" SLIPSTREAM_PREFIX "/bin:/usr/bin:/bin:/usr/sbin:/sbin","HOME=/var/root",NULL};
    environ=env;
    alarm(60);
    if (argc==2 && !strcmp(argv[1],"--latency")) return slipstream_provider_latency();
    if (argc!=1) deny();
    char *args[]={"slipstream","manage",NULL};
    execve(SLIPSTREAM_PREFIX "/usr/local/bin/slipstream",args,env);
    puts("{\"ok\":false,\"message\":\"The Slipstream service is missing. Reinstall Slipstream.\"}");
    return 1;
}
