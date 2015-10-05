/* seccomp-bpf constructor. Load a seccomp policy to the kernel restricting
 * socket operations to AF_UNIX
 */

/// TODO BELOW: FAIL AT AUTOTOOLS TODO
// I think this needs to be included from a src/lib/.deps/tsocks_seccomp.Plo
// but no idea how to do that
#include <features.h>
/// TODO ABOVE: FAIL AT AUTOTOOLS TODO

#include "torsocks.h"

#include <stdlib.h>

#ifdef USE_SECCOMP

#define TSOCKS_SCMP_ACT SCMP_ACT_KILL
// TODO consider SCMP_ACT_ERRNO

#define TSOCKS_SECCOMP_RULE(action, sys_name, ...) do { \
  int sys_num = seccomp_syscall_resolve_name_arch(arch, sys_name); \
  if(sys_num != __NR_SCMP_ERROR){ \
    if(seccomp_rule_add(ctx, action, sys_num, \
      __VA_ARGS__ ) < 0){ \
      printf("unable to add syscall %s rules for arch %d\n", sys_name, arch);\
      exit(EXIT_FAILURE); \
    } \
  }}while(0);

#define TSOCKS_SECCOMP_WHITELIST(sys_name, ...) TSOCKS_SECCOMP_RULE(SCMP_ACT_ALLOW, sys_name, __VA_ARGS__)
#define TSOCKS_SECCOMP_BLACKLIST(sys_name, ...) TSOCKS_SECCOMP_RULE(SCMP_ACT_KILL, sys_name, __VA_ARGS__)

static void tsocks_seccomp_init_add_rules(scmp_filter_ctx ctx, const uint32_t arch)
{
  // TODO hardening: should add prctl(PR_SET_DUMPABLE, false) for all linux to disable coredumps
  // PR_SET_NO_NEW_PRIVS
  // TODO man capabilitites: prctl(PR_SET_SECUREBITS, SECBIT_NOROOT);
  // TODO prctl(PR_SET_TSC, 0)
  printf("adding rules\n");

  printf("added whitelist\n");


  // disallow listening sockets:
  TSOCKS_SECCOMP_BLACKLIST("listen", 0)
  TSOCKS_SECCOMP_BLACKLIST("bind", 0)
  TSOCKS_SECCOMP_BLACKLIST("accept", 0)

  // only allow creation of sockets in the AF_UNIX namespace:
  // that is, only allow [named unix sockets] and [abstract unix sockets]
  TSOCKS_SECCOMP_BLACKLIST("socket", 1, SCMP_A0(SCMP_CMP_NE, PF_UNIX))
  // TODO consider blocking socketpair()
  //TSOCKS_SECCOMP_BLACKLIST("socket", 1, SCMP_A0(SCMP_CMP_NE, PF_NETLINK))

  // block socketcall() since it allows socket(), etc to be called.
  // BPF doesn't deref userspace pointers, so we can't examine the arguments.
  // x86 only has socketcall() TODO investigate, so we might want:
  ////// TSOCKS_SECCOMP_BLACKLIST("socketcall", 1, SCMP_A0(SCMP_CMP_EQ, SYS_SOCKET))
  #if defined( __i386__ )
    #define SYS_SOCKET 1
    // blacklist socket() on x86, but allow other socketcall()
    TSOCKS_SECCOMP_BLACKLIST("socketcall", 1, SCMP_A0(SCMP_CMP_EQ, SYS_SOCKET))
  #else
    TSOCKS_SECCOMP_BLACKLIST("socketcall", 0)
  #endif // __i386__

  // disable ptrace-related functions for process manipulation
  TSOCKS_SECCOMP_BLACKLIST("ptrace", 0) // trace other processes
  TSOCKS_SECCOMP_BLACKLIST("process_vm_readv", 0) // trace other processes
  TSOCKS_SECCOMP_BLACKLIST("process_vm_writev", 0) // trace other processes

  // disable FS-related privileged operations
  TSOCKS_SECCOMP_BLACKLIST("mount", 0)  // mount new file systems
  TSOCKS_SECCOMP_BLACKLIST("umount", 0) // unmount currently mounted file systems
  TSOCKS_SECCOMP_BLACKLIST("umount2", 0) // unmount currently mounted file systems
  TSOCKS_SECCOMP_BLACKLIST("mknod", 0)

  // disable generally dodgy syscalls
  TSOCKS_SECCOMP_BLACKLIST("sethostname", 0)
  TSOCKS_SECCOMP_BLACKLIST("reboot", 0)
  TSOCKS_SECCOMP_BLACKLIST("swapon", 0) // enable swap (paging to disk)
  TSOCKS_SECCOMP_BLACKLIST("ioperm", 0)
  TSOCKS_SECCOMP_BLACKLIST("iopl", 0)
  TSOCKS_SECCOMP_BLACKLIST("vm86", 0)
  TSOCKS_SECCOMP_BLACKLIST("kcmp", 0)
  TSOCKS_SECCOMP_BLACKLIST("vm86old", 0)
  TSOCKS_SECCOMP_BLACKLIST("setdomainname", 0)
  TSOCKS_SECCOMP_BLACKLIST("newuname", 0)
  TSOCKS_SECCOMP_BLACKLIST("migrate_pages", 0)

  // disallow operations related to loadable kernel modules
  TSOCKS_SECCOMP_BLACKLIST("create_module", 0)
  TSOCKS_SECCOMP_BLACKLIST("init_module", 0)
  TSOCKS_SECCOMP_BLACKLIST("finit_module", 0)
  TSOCKS_SECCOMP_BLACKLIST("delete_module", 0)
  TSOCKS_SECCOMP_BLACKLIST("kexec_load", 0)

  // disable PCI device manipulation
  TSOCKS_SECCOMP_BLACKLIST("pciconfig_iobase", 0)
  TSOCKS_SECCOMP_BLACKLIST("pciconfig_read", 0)
  TSOCKS_SECCOMP_BLACKLIST("pciconfig_write", 0)

  // control kernel nfs daemon
  TSOCKS_SECCOMP_BLACKLIST("nfsservctl", 0)

  // disable "key" manipulation
  TSOCKS_SECCOMP_BLACKLIST("keyctl", 0)
  TSOCKS_SECCOMP_BLACKLIST("request_key", 0)
  TSOCKS_SECCOMP_BLACKLIST("add_key", 0)

  // limit access to setting time
  TSOCKS_SECCOMP_BLACKLIST("stime", 0)  // set system time
  TSOCKS_SECCOMP_BLACKLIST("clock_adjtime", 0) // TODO INVESTIGATE
  TSOCKS_SECCOMP_BLACKLIST("clock_settime", 0) // TODO INVESTIGATE

  printf("added blacklist\n");
}

static scmp_filter_ctx * tsocks_seccomp_init_arch(scmp_filter_ctx src_ctx, const uint32_t arch){
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

  if(0 == seccomp_arch_exist(src_ctx, arch)){
    // already exists in the context
    return src_ctx;
  }

  printf("arch_add\n");
  if(seccomp_arch_add(ctx, arch) < 0){
    printf("arch: %d", arch);
    exit(EXIT_FAILURE);
  }

  tsocks_seccomp_init_add_rules(ctx, arch);

  printf("merging contexts\n");
  if(seccomp_merge(ctx, src_ctx) < 0){
    exit(EXIT_FAILURE);
  }

  return ctx;
}
#endif // USE_SECCOMP

void __inline__ tsocks_seccomp_init(void){
#ifdef USE_SECCOMP
  int ret = -1;

  scmp_filter_ctx ctx;

  printf("initializing archs\n");

  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if(ctx == NULL){
    exit(EXIT_FAILURE);
  }

  tsocks_seccomp_init_add_rules(ctx, SCMP_ARCH_NATIVE);

  printf("initialized arch NATIVE\n");

  // since the user could be cross-compiling,
  // add as many archs as possible:
  // TODO does seccomp support more than libseccomp?

  // not working:
  //ctx = tsocks_seccomp_init_arch(ctx, SCMP_ARCH_X32);
  //ctx = tsocks_seccomp_init_arch(ctx, SCMP_ARCH_X86);

  // working
  //ctx = tsocks_seccomp_init_arch(ctx, SCMP_ARCH_X86_64);

  // almost working
  ////ctx = tsocks_seccomp_init_arch(ctx, SCMP_ARCH_ARM);

  #ifdef SCMP_FLTATR_CTL_TSYNC
  // synchronize filter across all threads on seccomp_load()
  // TODO SCMP_FLTATR_ACT_BADARCH
  printf("synchronizing filters\n");
  ret = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);
  if(ret < 0){
    exit(EXIT_FAILURE);
  }
  #endif

  // commit the ruleset to the kernel
  printf("loading policy");
  ret = seccomp_load(ctx);
  if(ret < 0){
    exit(EXIT_FAILURE);
  }

  printf("releasing context\n");
  seccomp_release(ctx);
  printf("seccomp loaded\n");

#endif // USE_SECCOMP
}

