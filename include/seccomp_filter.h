#ifndef NANOROCK_SECCOMP_FILTER_H
#define NANOROCK_SECCOMP_FILTER_H

/* Installs a baseline BPF seccomp filter using raw BPF instructions without libseccomp.
 * Validates architecture (AUDIT_ARCH_X86_64) and blocks dangerous kernel-affecting
 * syscalls (reboot, kexec, ptrace, keyctl, userfaultfd, etc.) with SECCOMP_RET_ERRNO(EPERM).
 * Must be called AFTER prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).
 * Returns 0 on success, -1 on error (errno set). */
int seccomp_install_filter(void);

#endif /* NANOROCK_SECCOMP_FILTER_H */
