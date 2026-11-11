#ifndef NANOROCK_NETWORK_H
#define NANOROCK_NETWORK_H

#include <sys/types.h>
#include "config.h"

/* Brings up the loopback (lo) interface inside the current network namespace
 * using a raw AF_INET socket and SIOCSIFFLAGS ioctl.
 * Zero external binary dependencies (no /bin/sh, no iproute2).
 * Returns 0 on success, -1 on error (errno set). */
int network_up_lo(void);

/* Brings up an interface by name (e.g. "lo", "eth0", "nr-veth-...") via ioctl SIOCSIFFLAGS.
 * Returns 0 on success, -1 on error (errno set). */
int network_iface_up(const char *ifname);

/* Validates an IPv4 address string (dotted decimal format).
 * Returns 0 if valid, -1 if invalid. */
int network_validate_ip(const char *ip);

/* Validates a CIDR prefix length (1 to 30).
 * Returns 0 if valid, -1 if invalid. */
int network_validate_prefix(int prefix);

/* Host-side privileged network setup:
 * 1. Generates collision-resistant host interface name "nr-veth-<child_pid>".
 * 2. Creates veth pair using raw Netlink RTM_NEWLINK.
 * 3. Assigns host IPv4 address (e.g. 10.200.0.1/24) via Netlink RTM_NEWADDR.
 * 4. Brings host veth UP via ioctl SIOCSIFFLAGS.
 * 5. Opens /proc/<child_pid>/ns/net (O_CLOEXEC) and moves peer into child netns
 *    renamed directly to "eth0" using Netlink RTM_SETLINK (IFLA_NET_NS_FD).
 * Returns 0 on success, -1 on error (with cleanup on partial failure). */
int network_host_setup(pid_t child_pid, nanorock_config_t *cfg);

/* Child-side network setup (runs inside child network namespace before dropping caps):
 * 1. Assigns container IPv4 address (e.g. 10.200.0.2/24) to eth0 via Netlink RTM_NEWADDR.
 * 2. Brings eth0 UP via ioctl SIOCSIFFLAGS.
 * 3. Configures default route via host IP through eth0 via Netlink RTM_NEWROUTE.
 * 4. Verifies both lo and eth0 are UP and functional.
 * Returns 0 on success, -1 on error. */
int network_child_setup(const nanorock_config_t *cfg);

/* Deletes the host-side veth interface using Netlink RTM_DELLINK.
 * Automatically cleans up the peer interface in the container netns.
 * Gracefully ignores ENODEV/ESRCH if already cleaned up.
 * Returns 0 on success (or already gone), -1 on error. */
int network_host_cleanup(const char *host_veth);

#endif /* NANOROCK_NETWORK_H */
