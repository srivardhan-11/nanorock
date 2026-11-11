#ifndef NANOROCK_ERROR_H
#define NANOROCK_ERROR_H

#include <stdint.h>

#define NANOROCK_ERR_MSG_MAX 256

typedef enum {
    ERR_PHASE_NONE = 0,
    ERR_PHASE_SYNC_INIT,
    ERR_PHASE_HOSTNAME,
    ERR_PHASE_MOUNT_PRIVATE,
    ERR_PHASE_MOUNT_BIND,
    ERR_PHASE_CHDIR_ROOTFS,
    ERR_PHASE_MKDIR_OLDROOT,
    ERR_PHASE_PIVOT_ROOT,
    ERR_PHASE_CHDIR_NEWROOT,
    ERR_PHASE_UMOUNT_OLDROOT,
    ERR_PHASE_RMDIR_OLDROOT,
    ERR_PHASE_MOUNT_PROC,
    ERR_PHASE_MOUNT_DEV,
    ERR_PHASE_DEV_NODES,
    ERR_PHASE_NETWORK,
    ERR_PHASE_FD_HYGIENE,
    ERR_PHASE_SYNC_WAIT,
    ERR_PHASE_CAPABILITIES,
    ERR_PHASE_NO_NEW_PRIVS,
    ERR_PHASE_SECCOMP,
    ERR_PHASE_EXEC
} nanorock_error_phase_t;

typedef struct {
    uint32_t phase;                  /* nanorock_error_phase_t */
    int32_t  err_num;                /* errno value */
    char     msg[NANOROCK_ERR_MSG_MAX]; /* human-readable context */
} nanorock_error_t;

static inline const char *nanorock_phase_str(nanorock_error_phase_t phase) {
    switch (phase) {
    case ERR_PHASE_NONE:          return "none";
    case ERR_PHASE_SYNC_INIT:     return "synchronization pipe setup";
    case ERR_PHASE_HOSTNAME:      return "set hostname";
    case ERR_PHASE_MOUNT_PRIVATE: return "make mount namespace private";
    case ERR_PHASE_MOUNT_BIND:    return "bind-mount rootfs";
    case ERR_PHASE_CHDIR_ROOTFS:  return "chdir into rootfs";
    case ERR_PHASE_MKDIR_OLDROOT: return "create old-root mountpoint";
    case ERR_PHASE_PIVOT_ROOT:    return "pivot_root";
    case ERR_PHASE_CHDIR_NEWROOT: return "chdir to new root";
    case ERR_PHASE_UMOUNT_OLDROOT:return "unmount old root";
    case ERR_PHASE_RMDIR_OLDROOT: return "remove old root directory";
    case ERR_PHASE_MOUNT_PROC:    return "mount /proc";
    case ERR_PHASE_MOUNT_DEV:     return "mount private tmpfs on /dev";
    case ERR_PHASE_DEV_NODES:     return "create initial device nodes";
    case ERR_PHASE_NETWORK:       return "bring up loopback interface";
    case ERR_PHASE_FD_HYGIENE:    return "close inherited file descriptors";
    case ERR_PHASE_SYNC_WAIT:     return "wait for cgroup synchronization";
    case ERR_PHASE_CAPABILITIES:  return "drop bounding capabilities";
    case ERR_PHASE_NO_NEW_PRIVS:  return "set PR_SET_NO_NEW_PRIVS";
    case ERR_PHASE_SECCOMP:       return "install seccomp-BPF filter";
    case ERR_PHASE_EXEC:          return "exec user workload";
    default:                      return "unknown phase";
    }
}

#endif /* NANOROCK_ERROR_H */
