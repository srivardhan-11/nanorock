#ifndef NANOROCK_CAPABILITIES_H
#define NANOROCK_CAPABILITIES_H

/* Hardens the container's capability model:
 * 1. Clears all ambient capabilities (PR_CAP_AMBIENT_CLEAR_ALL).
 * 2. Clears all inheritable capabilities (via raw capset).
 * 3. Drops dangerous capabilities from the bounding set (PR_CAPBSET_DROP).
 * Must be called after all privileged setup (mounts, device nodes, loopback) is complete,
 * and immediately before no_new_privs and seccomp.
 * Returns 0 on success, -1 on error. */
int capabilities_drop(void);

#endif /* NANOROCK_CAPABILITIES_H */
