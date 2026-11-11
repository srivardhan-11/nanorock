#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Exact 21 capabilities dropped by Nanorock in src/capabilities.c:
 * Bits 0-31:
 *   Bit 2:  CAP_DAC_READ_SEARCH (0x4)
 *   Bit 12: CAP_NET_ADMIN       (0x1000)
 *   Bit 16: CAP_SYS_MODULE      (0x10000)
 *   Bit 17: CAP_SYS_RAWIO       (0x20000)
 *   Bit 19: CAP_SYS_PTRACE      (0x80000)
 *   Bit 20: CAP_SYS_PACCT       (0x100000)
 *   Bit 21: CAP_SYS_ADMIN       (0x200000)
 *   Bit 22: CAP_SYS_BOOT        (0x400000)
 *   Bit 24: CAP_SYS_RESOURCE    (0x1000000)
 *   Bit 25: CAP_SYS_TIME        (0x2000000)
 *   Bit 26: CAP_SYS_TTY_CONFIG  (0x4000000)
 *   Bit 30: CAP_AUDIT_CONTROL   (0x40000000)
 *   Sum low: 0x477b1004ULL
 * Bits 32-40:
 *   Bit 32: CAP_MAC_OVERRIDE
 *   Bit 33: CAP_MAC_ADMIN
 *   Bit 34: CAP_SYSLOG
 *   Bit 35: CAP_WAKE_ALARM
 *   Bit 36: CAP_BLOCK_SUSPEND
 *   Bit 37: CAP_AUDIT_READ
 *   Bit 38: CAP_PERFMON
 *   Bit 39: CAP_BPF
 *   Bit 40: CAP_CHECKPOINT_RESTORE
 *   Sum high: 0x1ffULL (shifted right 32)
 */
#define DROPPED_CAPS_MASK ((0x1ffULL << 32) | 0x477b1004ULL)

static int assert_denied(long syscall_nr, const char *name, long arg1, long arg2, long arg3, long arg4) {
    errno = 0;
    long ret = syscall(syscall_nr, arg1, arg2, arg3, arg4, 0);
    int err = errno;
    if (err == ENOSYS) {
        printf("  UNAVAILABLE: %s returned ENOSYS (not supported by kernel)\n", name);
        return 0;
    }
    if (ret != -1 || err != EPERM) {
        fprintf(stderr, "  FAIL: %s was not denied with EPERM (ret=%ld, errno=%d [%s])\n",
                name, ret, err, strerror(err));
        return -1;
    }
    printf("  PASS: %s denied with EPERM as expected\n", name);
    return 0;
}

int main(void) {
    printf("=== Running In-Container Security Probe ===\n");
    int failed = 0;

    /* Buffers for /proc/self/status values */
    uid_t ruid = (uid_t)-1, euid = (uid_t)-1, suid = (uid_t)-1, fsuid = (uid_t)-1;
    gid_t rgid = (gid_t)-1, egid = (gid_t)-1, sgid = (gid_t)-1, fsgid = (gid_t)-1;
    char cap_inh_str[64] = {0}, cap_prm_str[64] = {0}, cap_eff_str[64] = {0};
    char cap_bnd_str[64] = {0}, cap_amb_str[64] = {0};
    unsigned long long cap_inh = 0, cap_prm = 0, cap_eff = 0, cap_bnd = 0, cap_amb = 0;
    int nnp_val = -1, seccomp_val = -1, seccomp_filters = -1;

    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        fprintf(stderr, "  FAIL: Could not open /proc/self/status: %s\n", strerror(errno));
        return 1;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:\t", 5) == 0) {
            sscanf(line + 5, "%u\t%u\t%u\t%u", &ruid, &euid, &suid, &fsuid);
        } else if (strncmp(line, "Gid:\t", 5) == 0) {
            sscanf(line + 5, "%u\t%u\t%u\t%u", &rgid, &egid, &sgid, &fsgid);
        } else if (strncmp(line, "CapInh:\t", 8) == 0) {
            sscanf(line + 8, "%63s", cap_inh_str);
            cap_inh = strtoull(cap_inh_str, NULL, 16);
        } else if (strncmp(line, "CapPrm:\t", 8) == 0) {
            sscanf(line + 8, "%63s", cap_prm_str);
            cap_prm = strtoull(cap_prm_str, NULL, 16);
        } else if (strncmp(line, "CapEff:\t", 8) == 0) {
            sscanf(line + 8, "%63s", cap_eff_str);
            cap_eff = strtoull(cap_eff_str, NULL, 16);
        } else if (strncmp(line, "CapBnd:\t", 8) == 0) {
            sscanf(line + 8, "%63s", cap_bnd_str);
            cap_bnd = strtoull(cap_bnd_str, NULL, 16);
        } else if (strncmp(line, "CapAmb:\t", 8) == 0) {
            sscanf(line + 8, "%63s", cap_amb_str);
            cap_amb = strtoull(cap_amb_str, NULL, 16);
        } else if (strncmp(line, "NoNewPrivs:\t", 12) == 0) {
            nnp_val = atoi(line + 12);
        } else if (strncmp(line, "Seccomp:\t", 9) == 0) {
            seccomp_val = atoi(line + 9);
        } else if (strncmp(line, "Seccomp_filters:\t", 17) == 0) {
            seccomp_filters = atoi(line + 17);
        }
    }
    fclose(f);

    /* 1. Report Credentials and Privileges */
    printf("\nCredential state:\n");
    printf("  Uid:  %u (real=%u, eff=%u, saved=%u, fs=%u)\n", ruid, ruid, euid, suid, fsuid);
    printf("  Gid:  %u (real=%u, eff=%u, saved=%u, fs=%u)\n", rgid, rgid, egid, sgid, fsgid);

    printf("\nCapability state:\n");
    printf("  CapInh: %016llx (%s)\n", cap_inh, cap_inh_str);
    printf("  CapPrm: %016llx (%s)\n", cap_prm, cap_prm_str);
    printf("  CapEff: %016llx (%s)\n", cap_eff, cap_eff_str);
    printf("  CapBnd: %016llx (%s)\n", cap_bnd, cap_bnd_str);
    printf("  CapAmb: %016llx (%s)\n", cap_amb, cap_amb_str);

    printf("\nPrivilege state:\n");
    printf("  NoNewPrivs:      %d\n", nnp_val);
    printf("  Seccomp:         %d\n", seccomp_val);
    printf("  Seccomp_filters: %d\n\n", seccomp_filters);

    /* 2. Assert Invariants */
    if (ruid != 0 || euid != 0) {
        fprintf(stderr, "  FAIL: Container expected UID 0, got ruid=%u euid=%u\n", ruid, euid);
        failed = 1;
    } else {
        printf("  PASS: In-container process is UID 0 (root)\n");
    }

    if (cap_amb != 0) {
        fprintf(stderr, "  FAIL: CapAmb is non-zero: %016llx\n", cap_amb);
        failed = 1;
    } else {
        printf("  PASS: CapAmb is completely cleared (0)\n");
    }

    if (cap_inh != 0) {
        fprintf(stderr, "  FAIL: CapInh is non-zero: %016llx\n", cap_inh);
        failed = 1;
    } else {
        printf("  PASS: CapInh is completely zeroed (0)\n");
    }

    /* Check CapBnd has stripped dangerous capabilities */
    if ((cap_bnd & DROPPED_CAPS_MASK) != 0) {
        fprintf(stderr, "  FAIL: CapBnd retains dangerous capability bits: %016llx\n",
                cap_bnd & DROPPED_CAPS_MASK);
        failed = 1;
    } else {
        printf("  PASS: CapBnd has all 21 dangerous capabilities stripped (matches 0x%016llx)\n",
               cap_bnd);
    }

    /* Check post-exec CapPrm and CapEff match CapBnd and retain NO dangerous capabilities */
    if ((cap_prm & DROPPED_CAPS_MASK) != 0) {
        fprintf(stderr, "  FAIL: Post-exec CapPrm retains dangerous capabilities: %016llx\n",
                cap_prm & DROPPED_CAPS_MASK);
        failed = 1;
    } else if (cap_prm != cap_bnd) {
        fprintf(stderr, "  FAIL: Post-exec CapPrm (%016llx) != CapBnd (%016llx)\n",
                cap_prm, cap_bnd);
        failed = 1;
    } else {
        printf("  PASS: Post-exec CapPrm is strictly bounded by CapBnd with 0 dangerous capabilities\n");
    }

    if ((cap_eff & DROPPED_CAPS_MASK) != 0) {
        fprintf(stderr, "  FAIL: Post-exec CapEff retains dangerous capabilities: %016llx\n",
                cap_eff & DROPPED_CAPS_MASK);
        failed = 1;
    } else if (cap_eff != cap_bnd) {
        fprintf(stderr, "  FAIL: Post-exec CapEff (%016llx) != CapBnd (%016llx)\n",
                cap_eff, cap_bnd);
        failed = 1;
    } else {
        printf("  PASS: Post-exec CapEff is strictly bounded by CapBnd with 0 dangerous capabilities\n");
    }

    /* Verify NoNewPrivs */
    int nnp_prctl = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (nnp_val != 1 || nnp_prctl != 1) {
        fprintf(stderr, "  FAIL: NoNewPrivs not 1 (proc=%d, prctl=%d)\n", nnp_val, nnp_prctl);
        failed = 1;
    } else {
        printf("  PASS: NoNewPrivs is verified active (1) via both /proc and prctl\n");
    }

    /* Verify Seccomp */
    if (seccomp_val != 2 || seccomp_filters != 1) {
        fprintf(stderr, "  FAIL: Seccomp expected mode 2 with 1 filter (got mode=%d, filters=%d)\n",
                seccomp_val, seccomp_filters);
        failed = 1;
    } else {
        printf("  PASS: Seccomp mode is 2 (FILTER) with exactly 1 active filter\n");
    }

    /* 3. Behavioral Capability Operations Checks */
    printf("\nBehavioral Capability Checks:\n");
    /* Test CAP_SYS_TIME: clock_settime must fail with EPERM */
    struct timespec ts = { .tv_sec = 1000, .tv_nsec = 0 };
    errno = 0;
    if (clock_settime(CLOCK_REALTIME, &ts) == 0) {
        fprintf(stderr, "  FAIL: clock_settime succeeded (CAP_SYS_TIME was not dropped!)\n");
        failed = 1;
    } else {
        if (errno == EPERM) {
            printf("  PASS: clock_settime denied with EPERM (CAP_SYS_TIME dropped)\n");
        } else {
            fprintf(stderr, "  FAIL: clock_settime failed with unexpected errno=%d (%s)\n",
                    errno, strerror(errno));
            failed = 1;
        }
    }

    /* Test CAP_SYS_RAWIO: iopl must fail with EPERM (or UNAVAILABLE if not implemented) */
    errno = 0;
    int iopl_ret = syscall(SYS_iopl, 3);
    int iopl_err = errno;
    if (iopl_ret == 0) {
        fprintf(stderr, "  FAIL: iopl(3) succeeded (CAP_SYS_RAWIO was not dropped!)\n");
        failed = 1;
    } else if (iopl_err == EPERM) {
        printf("  PASS: iopl(3) denied with EPERM (CAP_SYS_RAWIO dropped)\n");
    } else if (iopl_err == ENOSYS) {
        printf("  UNAVAILABLE: iopl returned ENOSYS on this platform\n");
    } else {
        fprintf(stderr, "  FAIL: iopl failed with unexpected errno=%d (%s)\n",
                iopl_err, strerror(iopl_err));
        failed = 1;
    }

    /* Test CAP_NET_ADMIN: SIOCSIFFLAGS on loopback must fail with EPERM */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
        ifr.ifr_flags = 0; /* try to set flags */
        errno = 0;
        int ioctl_ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
        int ioctl_err = errno;
        close(sock);
        if (ioctl_ret == 0) {
            fprintf(stderr, "  FAIL: SIOCSIFFLAGS succeeded (CAP_NET_ADMIN was not dropped!)\n");
            failed = 1;
        } else if (ioctl_err == EPERM) {
            printf("  PASS: SIOCSIFFLAGS denied with EPERM (CAP_NET_ADMIN dropped)\n");
        } else if (ioctl_err == ENOSYS) {
            printf("  UNAVAILABLE: SIOCSIFFLAGS returned ENOSYS\n");
        } else {
            fprintf(stderr, "  FAIL: SIOCSIFFLAGS failed with unexpected errno=%d (%s)\n",
                    ioctl_err, strerror(ioctl_err));
            failed = 1;
        }
    } else {
        printf("  UNAVAILABLE: socket creation for network probe returned error\n");
    }

    /* 4. Behavioral Seccomp Filter Syscall Checks */
    printf("\nBehavioral Seccomp Filter Syscall Checks:\n");
    if (assert_denied(__NR_reboot, "reboot", 0xfee1dead, 672274793, 0x1234567, 0) != 0) failed = 1;
    if (assert_denied(__NR_mount, "mount", (long)"none", (long)"/tmp", (long)"tmpfs", 0) != 0) failed = 1;
    if (assert_denied(__NR_umount2, "umount2", (long)"/proc", 0, 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_pivot_root, "pivot_root", (long)".", (long)".", 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_unshare, "unshare", CLONE_NEWUSER, 0, 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_setns, "setns", 0, 0, 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_sethostname, "sethostname", (long)"hacked", 6, 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_setdomainname, "setdomainname", (long)"hacked", 6, 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_ptrace, "ptrace", 0, 0, 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_swapon, "swapon", (long)"/dev/null", 0, 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_swapoff, "swapoff", (long)"/dev/null", 0, 0, 0) != 0) failed = 1;
    if (assert_denied(__NR_init_module, "init_module", 0, 0, 0, 0) != 0) failed = 1;
#ifdef __NR_bpf
    if (assert_denied(__NR_bpf, "bpf", 0, 0, 0, 0) != 0) failed = 1;
#endif
#ifdef __NR_keyctl
    if (assert_denied(__NR_keyctl, "keyctl", 0, 0, 0, 0) != 0) failed = 1;
#endif
#ifdef __NR_open_by_handle_at
    if (assert_denied(__NR_open_by_handle_at, "open_by_handle_at", -1, 0, 0, 0) != 0) failed = 1;
#endif
#ifdef __NR_name_to_handle_at
    if (assert_denied(__NR_name_to_handle_at, "name_to_handle_at", -1, 0, 0, 0) != 0) failed = 1;
#endif
#ifdef __NR_io_uring_setup
    if (assert_denied(__NR_io_uring_setup, "io_uring_setup", 0, 0, 0, 0) != 0) failed = 1;
#endif
#ifdef __NR_process_vm_readv
    if (assert_denied(__NR_process_vm_readv, "process_vm_readv", 0, 0, 0, 0) != 0) failed = 1;
#endif
#ifdef __NR_process_vm_writev
    if (assert_denied(__NR_process_vm_writev, "process_vm_writev", 0, 0, 0, 0) != 0) failed = 1;
#endif
#ifdef __NR_perf_event_open
    if (assert_denied(__NR_perf_event_open, "perf_event_open", 0, 0, 0, 0) != 0) failed = 1;
#endif
#ifdef __NR_userfaultfd
    if (assert_denied(__NR_userfaultfd, "userfaultfd", 0, 0, 0, 0) != 0) failed = 1;
#endif

    printf("\n");
    if (failed == 0) {
        printf("SECURITY_PROBE_SUCCESS\n");
        return 0;
    } else {
        printf("SECURITY_PROBE_FAILED\n");
        return 1;
    }
}
