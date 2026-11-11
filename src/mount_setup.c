#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "log.h"
#include "mount_setup.h"

static int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

static void set_err(nanorock_error_t *err, nanorock_error_phase_t phase, int err_num, const char *msg) {
    if (err != NULL) {
        err->phase = phase;
        err->err_num = err_num;
        strncpy(err->msg, msg, sizeof(err->msg) - 1);
        err->msg[sizeof(err->msg) - 1] = '\0';
    }
}

int mount_validate_rootfs(const nanorock_config_t *cfg, nanorock_error_t *err) {
    if (cfg == NULL || cfg->rootfs == NULL || cfg->rootfs[0] == '\0') {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, EINVAL, "rootfs path is empty or NULL");
        return -1;
    }

    char resolved[PATH_MAX];
    if (realpath(cfg->rootfs, resolved) == NULL) {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, errno, "failed to resolve rootfs canonical path");
        return -1;
    }

    if (strcmp(resolved, "/") == 0) {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, EINVAL, "refusing to use host root '/' as container rootfs");
        return -1;
    }

    if (strcmp(resolved, "/proc") == 0 || strcmp(resolved, "/sys") == 0 ||
        strcmp(resolved, "/dev") == 0 || strcmp(resolved, "/sys/fs/cgroup") == 0) {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, EINVAL, "refusing to use host virtual mount as container rootfs");
        return -1;
    }

    struct stat st;
    if (stat(resolved, &st) != 0) {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, errno, "stat failed on rootfs directory");
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, ENOTDIR, "rootfs path is not a directory");
        return -1;
    }

    if (access(resolved, R_OK | X_OK) != 0) {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, errno, "rootfs directory lacks read/execute permissions");
        return -1;
    }

    return 0;
}

static int make_dev_node(const char *path, mode_t mode, dev_t dev) {
    if (mknod(path, mode, dev) != 0) {
        if (errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

int mount_setup_rootfs(const nanorock_config_t *cfg, nanorock_error_t *err) {
    if (mount_validate_rootfs(cfg, err) != 0) {
        return -1;
    }

    char resolved_rootfs[PATH_MAX];
    if (realpath(cfg->rootfs, resolved_rootfs) == NULL) {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, errno, "failed to resolve rootfs canonical path");
        return -1;
    }

    /* 1. Detach our mount tree from the host: prevent mount propagation back out. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        set_err(err, ERR_PHASE_MOUNT_PRIVATE, errno, "failed to make mount namespace private");
        return -1;
    }

    /* 2. pivot_root requires new_root to be a mount point: bind-mount onto itself. */
    if (mount(resolved_rootfs, resolved_rootfs, NULL, MS_BIND | MS_REC, NULL) != 0) {
        set_err(err, ERR_PHASE_MOUNT_BIND, errno, "failed to bind-mount rootfs onto itself");
        return -1;
    }

    if (chdir(resolved_rootfs) != 0) {
        set_err(err, ERR_PHASE_CHDIR_ROOTFS, errno, "failed to chdir into rootfs");
        return -1;
    }

    /* 3. Swap rootfs in as "/", placing old root at unique temporary directory */
    char old_root_template[] = ".oldroot_XXXXXX";
    char *old_root_dir = mkdtemp(old_root_template);
    if (old_root_dir == NULL) {
        set_err(err, ERR_PHASE_MKDIR_OLDROOT, errno, "failed to create unique old-root directory");
        return -1;
    }

    if (pivot_root(".", old_root_dir) != 0) {
        set_err(err, ERR_PHASE_PIVOT_ROOT, errno, "pivot_root syscall failed");
        rmdir(old_root_dir);
        return -1;
    }

    if (chdir("/") != 0) {
        set_err(err, ERR_PHASE_CHDIR_NEWROOT, errno, "failed to chdir to new root / after pivot_root");
        return -1;
    }

    /* 4. Detach old root. Invariant: MUST fail closed if detachment fails! */
    char old_root_path[128];
    snprintf(old_root_path, sizeof(old_root_path), "/%s", old_root_dir);

    if (umount2(old_root_path, MNT_DETACH) != 0) {
        set_err(err, ERR_PHASE_UMOUNT_OLDROOT, errno, "failed to detach old root filesystem");
        return -1;
    }
    rmdir(old_root_path);

    /* 5. Mount a fresh /proc for the container's PID namespace */
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0) {
        set_err(err, ERR_PHASE_MOUNT_PROC, errno, "failed to mount container /proc");
        return -1;
    }

    /* 6. Mount private in-memory tmpfs on /dev: zero mutation of host storage */
    mkdir("/dev", 0755);
    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=0755") != 0) {
        set_err(err, ERR_PHASE_MOUNT_DEV, errno, "failed to mount private tmpfs on /dev");
        return -1;
    }

    /* 7. Populate minimal required device nodes on the private tmpfs */
    if (make_dev_node("/dev/null", S_IFCHR | 0666, makedev(1, 3)) != 0 ||
        make_dev_node("/dev/zero", S_IFCHR | 0666, makedev(1, 5)) != 0 ||
        make_dev_node("/dev/full", S_IFCHR | 0666, makedev(1, 7)) != 0 ||
        make_dev_node("/dev/random", S_IFCHR | 0666, makedev(1, 8)) != 0 ||
        make_dev_node("/dev/urandom", S_IFCHR | 0666, makedev(1, 9)) != 0 ||
        make_dev_node("/dev/tty", S_IFCHR | 0666, makedev(5, 0)) != 0) {
        set_err(err, ERR_PHASE_DEV_NODES, errno, "failed to create essential device node in /dev tmpfs");
        return -1;
    }

    /* 8. Optional devpts mount and standard stdio / fd symlinks */
    mkdir("/dev/pts", 0755);
    mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620");

    symlink("/dev/pts/ptmx", "/dev/ptmx");
    symlink("/proc/self/fd", "/dev/fd");
    symlink("/proc/self/fd/0", "/dev/stdin");
    symlink("/proc/self/fd/1", "/dev/stdout");
    symlink("/proc/self/fd/2", "/dev/stderr");

    return 0;
}
