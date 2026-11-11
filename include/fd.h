#ifndef NANOROCK_FD_H
#define NANOROCK_FD_H

#include <stddef.h>

/* Closes all open file descriptors > 2 (STDERR_FILENO), EXCEPT those listed in keep_fds.
 * keep_fds is an array of count file descriptors to preserve (e.g., sync pipes).
 * Standard descriptors 0, 1, 2 (stdin, stdout, stderr) are always preserved.
 *
 * Scans /proc/self/fd if available, otherwise iterates up to sysconf(_SC_OPEN_MAX).
 * Returns 0 on success, -1 on error. */
int fd_close_except(const int *keep_fds, size_t count);

#endif /* NANOROCK_FD_H */
