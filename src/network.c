#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "network.h"

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen) {
    int len = RTA_LENGTH(alen);
    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > (unsigned int)maxlen) {
        return -1;
    }
    struct rtattr *rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen) {
        memcpy(RTA_DATA(rta), data, alen);
    }
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

static struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type) {
    struct rtattr *nest = NLMSG_TAIL(n);
    if (addattr_l(n, maxlen, type, NULL, 0) < 0) {
        return NULL;
    }
    return nest;
}

static int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest) {
    nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
    return n->nlmsg_len;
}

static int nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -1;
    }
    return fd;
}

static int nl_wait_ack(int nl_fd, uint32_t seq) {
    char recvbuf[4096];
    while (1) {
        ssize_t status = recv(nl_fd, recvbuf, sizeof(recvbuf), 0);
        if (status < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        for (struct nlmsghdr *resp = (struct nlmsghdr *)recvbuf;
             NLMSG_OK(resp, (unsigned int)status);
             resp = NLMSG_NEXT(resp, status)) {
            if (resp->nlmsg_seq != seq) {
                continue;
            }
            if (resp->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
                return err->error; /* 0 on success ACK, negative errno on failure */
            }
            if (resp->nlmsg_type == NLMSG_DONE) {
                return 0;
            }
        }
    }
}

int network_validate_ip(const char *ip) {
    if (!ip || ip[0] == '\0' || strlen(ip) >= 16) {
        return -1;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return -1;
    }
    return 0;
}

int network_validate_prefix(int prefix) {
    if (prefix < 1 || prefix > 30) {
        return -1;
    }
    return 0;
}

int network_iface_up(const char *ifname) {
    if (!ifname || ifname[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }

    close(sock);
    return 0;
}

int network_up_lo(void) {
    return network_iface_up("lo");
}

static int nl_set_ip(int nl_fd, const char *ifname, const char *ip_str, int prefixlen, uint32_t seq) {
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_type = RTM_NEWADDR;
    nlh->nlmsg_seq = seq;

    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = (unsigned char)prefixlen;
    ifa->ifa_flags = IFA_F_PERMANENT;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_index = if_nametoindex(ifname);
    if (ifa->ifa_index == 0) {
        return -1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        errno = EINVAL;
        return -1;
    }

    if (addattr_l(nlh, sizeof(buf), IFA_LOCAL, &addr, sizeof(addr)) < 0) {
        return -1;
    }
    if (addattr_l(nlh, sizeof(buf), IFA_ADDRESS, &addr, sizeof(addr)) < 0) {
        return -1;
    }

    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) < 0) {
        return -1;
    }
    int ack = nl_wait_ack(nl_fd, seq);
    if (ack != 0) {
        errno = -ack;
        return -1;
    }
    return 0;
}

static int nl_add_default_route(int nl_fd, const char *ifname, const char *gw_str, uint32_t seq) {
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_seq = seq;

    struct rtmsg *rt = (struct rtmsg *)NLMSG_DATA(nlh);
    rt->rtm_family = AF_INET;
    rt->rtm_dst_len = 0; /* 0.0.0.0/0 default route */
    rt->rtm_src_len = 0;
    rt->rtm_tos = 0;
    rt->rtm_table = RT_TABLE_MAIN;
    rt->rtm_protocol = RTPROT_BOOT;
    rt->rtm_scope = RT_SCOPE_UNIVERSE;
    rt->rtm_type = RTN_UNICAST;
    rt->rtm_flags = 0;

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return -1;
    }
    if (addattr_l(nlh, sizeof(buf), RTA_OIF, &ifindex, sizeof(ifindex)) < 0) {
        return -1;
    }

    struct in_addr gw;
    if (inet_pton(AF_INET, gw_str, &gw) != 1) {
        errno = EINVAL;
        return -1;
    }
    if (addattr_l(nlh, sizeof(buf), RTA_GATEWAY, &gw, sizeof(gw)) < 0) {
        return -1;
    }

    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) < 0) {
        return -1;
    }
    int ack = nl_wait_ack(nl_fd, seq);
    if (ack != 0) {
        errno = -ack;
        return -1;
    }
    return 0;
}

static int nl_create_veth(int nl_fd, const char *host_name, const char *peer_name, uint32_t seq) {
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_seq = seq;

    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;

    if (addattr_l(nlh, sizeof(buf), IFLA_IFNAME, host_name, strlen(host_name) + 1) < 0) {
        return -1;
    }
    struct rtattr *linkinfo = addattr_nest(nlh, sizeof(buf), IFLA_LINKINFO);
    if (!linkinfo) {
        return -1;
    }
    if (addattr_l(nlh, sizeof(buf), IFLA_INFO_KIND, "veth", 5) < 0) {
        return -1;
    }
    struct rtattr *infodata = addattr_nest(nlh, sizeof(buf), IFLA_INFO_DATA);
    if (!infodata) {
        return -1;
    }
    struct rtattr *peer = addattr_nest(nlh, sizeof(buf), VETH_INFO_PEER);
    if (!peer) {
        return -1;
    }

    struct ifinfomsg peer_ifi;
    memset(&peer_ifi, 0, sizeof(peer_ifi));
    peer_ifi.ifi_family = AF_UNSPEC;
    int ifi_len = sizeof(peer_ifi);
    void *pdata = (void *)NLMSG_TAIL(nlh);
    memcpy(pdata, &peer_ifi, ifi_len);
    nlh->nlmsg_len += ifi_len;

    if (addattr_l(nlh, sizeof(buf), IFLA_IFNAME, peer_name, strlen(peer_name) + 1) < 0) {
        return -1;
    }
    addattr_nest_end(nlh, peer);
    addattr_nest_end(nlh, infodata);
    addattr_nest_end(nlh, linkinfo);

    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) < 0) {
        return -1;
    }
    int ack = nl_wait_ack(nl_fd, seq);
    if (ack != 0) {
        errno = -ack;
        return -1;
    }
    return 0;
}

static int nl_move_and_rename_peer(int nl_fd, const char *peer_name, int netns_fd, const char *new_name, uint32_t seq) {
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_type = RTM_SETLINK;
    nlh->nlmsg_seq = seq;

    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = if_nametoindex(peer_name);
    if (ifi->ifi_index == 0) {
        return -1;
    }

    if (addattr_l(nlh, sizeof(buf), IFLA_NET_NS_FD, &netns_fd, sizeof(netns_fd)) < 0) {
        return -1;
    }
    if (addattr_l(nlh, sizeof(buf), IFLA_IFNAME, new_name, strlen(new_name) + 1) < 0) {
        return -1;
    }

    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) < 0) {
        return -1;
    }
    int ack = nl_wait_ack(nl_fd, seq);
    if (ack != 0) {
        errno = -ack;
        return -1;
    }
    return 0;
}

int network_host_cleanup(const char *host_veth) {
    if (!host_veth || host_veth[0] == '\0') {
        return 0;
    }
    int ifindex = if_nametoindex(host_veth);
    if (ifindex == 0) {
        /* Device already removed or does not exist */
        return 0;
    }

    int nl_fd = nl_open();
    if (nl_fd < 0) {
        return -1;
    }

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_type = RTM_DELLINK;
    nlh->nlmsg_seq = 99;

    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;

    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) < 0) {
        close(nl_fd);
        return -1;
    }

    int ack = nl_wait_ack(nl_fd, 99);
    close(nl_fd);

    if (ack != 0 && -ack != ENODEV && -ack != ESRCH) {
        errno = -ack;
        return -1;
    }
    return 0;
}

int network_host_setup(pid_t child_pid, nanorock_config_t *cfg) {
    if (!cfg || child_pid <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* 1. Generate collision-resistant host and temporary peer interface names (<= 15 chars) */
    snprintf(cfg->host_veth, sizeof(cfg->host_veth), "nrv-%d", child_pid);
    char peer_name[IFNAMSIZ];
    snprintf(peer_name, sizeof(peer_name), "nrp-%d", child_pid);

    /* 2. Open child network namespace descriptor while child is alive and waiting */
    char netns_path[64];
    snprintf(netns_path, sizeof(netns_path), "/proc/%d/ns/net", child_pid);
    int netns_fd = open(netns_path, O_RDONLY | O_CLOEXEC);
    if (netns_fd < 0) {
        log_error("network: failed to open child netns (%s): %s", netns_path, strerror(errno));
        return -1;
    }

    int nl_fd = nl_open();
    if (nl_fd < 0) {
        log_error("network: failed to open netlink socket: %s", strerror(errno));
        close(netns_fd);
        return -1;
    }

    /* 3. Create veth pair in host network namespace */
    if (nl_create_veth(nl_fd, cfg->host_veth, peer_name, 1) != 0) {
        log_error("network: failed to create veth pair (%s, %s): %s",
                  cfg->host_veth, peer_name, strerror(errno));
        close(nl_fd);
        close(netns_fd);
        return -1;
    }

    /* 4. Move temporary peer into child netns and rename directly to 'eth0' */
    if (nl_move_and_rename_peer(nl_fd, peer_name, netns_fd, "eth0", 2) != 0) {
        log_error("network: failed to move peer into child netns: %s", strerror(errno));
        network_host_cleanup(cfg->host_veth);
        close(nl_fd);
        close(netns_fd);
        return -1;
    }

    /* netns_fd no longer needed; close immediately */
    close(netns_fd);

    /* 5. Configure host-side veth IPv4 address */
    if (nl_set_ip(nl_fd, cfg->host_veth, cfg->host_ip, cfg->net_prefix, 3) != 0) {
        log_error("network: failed to set IP on host veth %s (%s/%d): %s",
                  cfg->host_veth, cfg->host_ip, cfg->net_prefix, strerror(errno));
        network_host_cleanup(cfg->host_veth);
        close(nl_fd);
        return -1;
    }

    close(nl_fd);

    /* 6. Bring host-side veth interface UP */
    if (network_iface_up(cfg->host_veth) != 0) {
        log_error("network: failed to bring host veth %s UP: %s",
                  cfg->host_veth, strerror(errno));
        network_host_cleanup(cfg->host_veth);
        return -1;
    }

    if (cfg->verbose) {
        log_verbose("network:");
        log_verbose("  netns: created");
        log_verbose("  veth host: %s", cfg->host_veth);
        log_verbose("  veth container: eth0");
        log_verbose("  host address: %s/%d", cfg->host_ip, cfg->net_prefix);
        log_verbose("  container address: %s/%d", cfg->container_ip, cfg->net_prefix);
        log_verbose("  network: ready");
    }

    return 0;
}

int network_child_setup(const nanorock_config_t *cfg) {
    if (!cfg) {
        errno = EINVAL;
        return -1;
    }

    int nl_fd = nl_open();
    if (nl_fd < 0) {
        return -1;
    }

    /* 1. Assign container IPv4 address to eth0 */
    if (nl_set_ip(nl_fd, "eth0", cfg->container_ip, cfg->net_prefix, 10) != 0) {
        close(nl_fd);
        return -1;
    }

    /* 2. Bring eth0 UP */
    if (network_iface_up("eth0") != 0) {
        close(nl_fd);
        return -1;
    }

    /* 3. Add default route via host IP */
    if (nl_add_default_route(nl_fd, "eth0", cfg->host_ip, 11) != 0) {
        close(nl_fd);
        return -1;
    }

    close(nl_fd);

    /* 4. Verify loopback (lo) and eth0 are UP */
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0 || !(ifr.ifr_flags & IFF_UP)) {
        close(sock);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0 || !(ifr.ifr_flags & IFF_UP)) {
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}
