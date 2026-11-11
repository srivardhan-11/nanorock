# Contributing to nanorock

`nanorock` is a minimal, educational Linux container runtime designed to demonstrate raw kernel container primitives without external libraries, daemons, or databases. Contributions that improve correctness, clarity, security, and verification are welcome.

## Building and Verification

All code must build cleanly under GCC with strict hardening flags:

```bash
make clean
make            # builds bin/nanorock
make rootfs     # generates minimal BusyBox test rootfs at ./rootfs
sudo make test  # executes complete 9-suite verification suite (206 assertions)
```

The build must pass with zero compiler warnings under:
* `-Wall -Wextra -Werror -std=gnu11`
* `-g -fstack-protector-strong -D_FORTIFY_SOURCE=2`
* `-fPIE -pie -Wl,-z,relro,-z,now`

## Code Standards & Architectural Invariants

1. **Direct Kernel Primitives**: Do not introduce dependencies on external container libraries (`libcap`, `libseccomp`, `libnetlink`), container engines, or persistent databases. Use direct Linux system calls, Netlink sockets, and kernel pseudo-filesystems.
2. **Strict Single Responsibility**: Keep subsystems modular. `namespaces.c` handles namespace creation; `mount_setup.c` handles `pivot_root` and mounts; `cgroups.c` handles cgroup v2 controllers; `network.c` handles Netlink veth configuration; `supervision.c` handles signal forwarding; `main.c` orchestrates the lifecycle.
3. **Fail-Closed Security**: Security boundaries (such as capability bounding drops, `no_new_privs`, raw seccomp filter installation, cgroup placement, and old root detachment) must never fail silently. If a requested security or resource control cannot be established, the runtime must clean up and abort with an error.
4. **FD Hygiene**: All internal file descriptors must be opened with `O_CLOEXEC` (or converted immediately). Internal descriptors must be closed prior to executing the user workload (`fd_close_except()`).
5. **Clear Systems Commentary**: Comments should explain *why* an operation exists, why a particular order is mandatory, and what kernel semantics are being satisfied. Avoid restating obvious code syntax.

## Submitting Pull Requests

1. **Preserve All Test Assertions**: PRs must not remove or weaken existing assertions in `tests/`. All 206 test assertions must pass.
2. **Whitespace and Formatting**: Verify code formatting using `git diff --check` before submitting.
3. **Focused Changes**: Keep changes modular and focused on a single subsystem, bugfix, or clarification.
