#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "log.h"
#include "seccomp_filter.h"

#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 0xc000003e
#endif

/* Convenience macro for BPF filter construction:
 * If syscall number matches, execute the immediate next instruction (return EPERM).
 * If it does not match, skip the next instruction (jump over the return statement). */
#define DENY_RULE(syscall_nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (syscall_nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

int seccomp_install_filter(void) {
    struct sock_filter filter[] = {
        /* [0] Load architecture from seccomp_data: offset 4 */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),

        /* [1] Validate architecture is x86_64. If match, skip 1 instruction. If mismatch, kill. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),

        /* [2] Mismatched architecture: fail closed */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* [3] Load syscall number from seccomp_data: offset 0 */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

        /* Kernel module loading / unloading */
        DENY_RULE(__NR_init_module),
        DENY_RULE(__NR_finit_module),
        DENY_RULE(__NR_delete_module),

        /* Reboot / kernel replacement */
        DENY_RULE(__NR_reboot),
        DENY_RULE(__NR_kexec_load),
#ifdef __NR_kexec_file_load
        DENY_RULE(__NR_kexec_file_load),
#endif

        /* Host swap manipulation */
        DENY_RULE(__NR_swapon),
        DENY_RULE(__NR_swapoff),

        /* Mount namespace mutations (runtime setup is already complete) */
        DENY_RULE(__NR_mount),
        DENY_RULE(__NR_umount2),
        DENY_RULE(__NR_pivot_root),

        /* Namespace creation and attachment */
        DENY_RULE(__NR_unshare),
        DENY_RULE(__NR_setns),

        /* Host identity */
        DENY_RULE(__NR_sethostname),
        DENY_RULE(__NR_setdomainname),

        /* Cross-process tracing and memory access */
        DENY_RULE(__NR_ptrace),
        DENY_RULE(__NR_process_vm_readv),
        DENY_RULE(__NR_process_vm_writev),

        /* High-risk kernel attack surface */
#ifdef __NR_bpf
        DENY_RULE(__NR_bpf),
#endif
#ifdef __NR_perf_event_open
        DENY_RULE(__NR_perf_event_open),
#endif
        DENY_RULE(__NR_keyctl),
        DENY_RULE(__NR_add_key),
        DENY_RULE(__NR_request_key),
#ifdef __NR_userfaultfd
        DENY_RULE(__NR_userfaultfd),
#endif
#ifdef __NR_io_uring_setup
        DENY_RULE(__NR_io_uring_setup),
#endif

        /* Direct file handle manipulation (known container escape vector) */
        DENY_RULE(__NR_open_by_handle_at),
        DENY_RULE(__NR_name_to_handle_at),

        /* Obsolete / dangerous syscalls */
        DENY_RULE(__NR_sysfs),
        DENY_RULE(__NR_uselib),
        DENY_RULE(__NR_acct),

        /* Default action: allow normal application syscalls */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        log_error("failed to install raw seccomp-BPF filter: %s", strerror(errno));
        return -1;
    }

    log_info("seccomp: installed raw BPF filter (%u instructions, arch x86_64, default ALLOW)",
             prog.len);
    return 0;
}
