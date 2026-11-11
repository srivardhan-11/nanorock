#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "capabilities.h"
#include "log.h"

/* Linux ambient capability prctl constants (kernel 4.3+) */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

typedef struct {
    int cap;
    const char *name;
} cap_entry_t;

/* Curated set of dangerous capabilities to drop from the bounding set.
 * These capabilities allow a process to reach outside the container boundary:
 * modifying host hardware, loading kernel modules, rebooting the host,
 * tracing host processes, configuring network routes, overriding MAC/SELinux,
 * or using privileged kernel interfaces like BPF or perfmon. */
static const cap_entry_t CAPS_TO_DROP[] = {
    {CAP_SYS_ADMIN,          "CAP_SYS_ADMIN"},
    {CAP_SYS_MODULE,         "CAP_SYS_MODULE"},
    {CAP_SYS_RAWIO,          "CAP_SYS_RAWIO"},
    {CAP_SYS_BOOT,           "CAP_SYS_BOOT"},
    {CAP_SYS_TIME,           "CAP_SYS_TIME"},
    {CAP_SYS_PACCT,          "CAP_SYS_PACCT"},
    {CAP_SYS_TTY_CONFIG,     "CAP_SYS_TTY_CONFIG"},
    {CAP_MAC_ADMIN,          "CAP_MAC_ADMIN"},
    {CAP_MAC_OVERRIDE,       "CAP_MAC_OVERRIDE"},
    {CAP_NET_ADMIN,          "CAP_NET_ADMIN"},
    {CAP_SYS_PTRACE,         "CAP_SYS_PTRACE"},
    {CAP_DAC_READ_SEARCH,    "CAP_DAC_READ_SEARCH"},
    {CAP_SYSLOG,             "CAP_SYSLOG"},
    {CAP_SYS_RESOURCE,       "CAP_SYS_RESOURCE"},
    {CAP_AUDIT_CONTROL,      "CAP_AUDIT_CONTROL"},
    {CAP_AUDIT_READ,         "CAP_AUDIT_READ"},
    {CAP_BLOCK_SUSPEND,      "CAP_BLOCK_SUSPEND"},
    {CAP_WAKE_ALARM,         "CAP_WAKE_ALARM"},
#ifdef CAP_BPF
    {CAP_BPF,                "CAP_BPF"},
#endif
#ifdef CAP_PERFMON
    {CAP_PERFMON,            "CAP_PERFMON"},
#endif
#ifdef CAP_CHECKPOINT_RESTORE
    {CAP_CHECKPOINT_RESTORE, "CAP_CHECKPOINT_RESTORE"},
#endif
};

#define NUM_CAPS_TO_DROP (sizeof(CAPS_TO_DROP) / sizeof(CAPS_TO_DROP[0]))

int capabilities_drop(void) {
    /* 1. Clear all ambient capabilities (prevents unprivileged ambient privilege inheritance) */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
        if (errno != EINVAL && errno != EOPNOTSUPP) {
            log_warn("could not clear ambient capabilities: %s", strerror(errno));
        }
    }

    /* 2. Clear inheritable capability set using raw capset syscall */
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));

    if (syscall(SYS_capget, &hdr, data) == 0) {
        data[0].inheritable = 0;
        data[1].inheritable = 0;
        if (syscall(SYS_capset, &hdr, data) != 0) {
            log_warn("could not clear inheritable capabilities: %s", strerror(errno));
        }
    }

    /* 3. Drop all dangerous capabilities from the bounding set */
    int dropped = 0;
    for (size_t i = 0; i < NUM_CAPS_TO_DROP; i++) {
        if (prctl(PR_CAPBSET_DROP, CAPS_TO_DROP[i].cap, 0, 0, 0) != 0) {
            /* EINVAL means this kernel does not recognize this capability */
            if (errno != EINVAL) {
                log_warn("could not drop %s from bounding set: %s",
                         CAPS_TO_DROP[i].name, strerror(errno));
            }
            continue;
        }
        dropped++;
    }

    log_info("capabilities: cleared ambient/inheritable, dropped %d/%zu from bounding set",
             dropped, NUM_CAPS_TO_DROP);
    return 0;
}
