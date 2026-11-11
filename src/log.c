#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

static void vlog(const char *level, const char *color, const char *fmt, va_list args) {
    fprintf(stderr, "%s[nanorock]\033[0m %-5s ", color, level);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog("INFO", "\033[36m", fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog("WARN", "\033[33m", fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog("ERROR", "\033[31m", fmt, args);
    va_end(args);
}

static int g_verbose_enabled = 0;

void log_set_verbose(int enable) {
    g_verbose_enabled = enable;
}

void log_verbose(const char *fmt, ...) {
    if (!g_verbose_enabled) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    vlog("DEBUG", "\033[35m", fmt, args);
    va_end(args);
}

void die(const char *fmt, ...) {
    int saved_errno = errno;
    va_list args;
    va_start(args, fmt);
    vlog("FATAL", "\033[31m", fmt, args);
    va_end(args);
    if (saved_errno != 0) {
        fprintf(stderr, "        errno: %s\n", strerror(saved_errno));
    }
    exit(EXIT_FAILURE);
}

void die_with_code(int exit_code, const char *fmt, ...) {
    int saved_errno = errno;
    va_list args;
    va_start(args, fmt);
    vlog("FATAL", "\033[31m", fmt, args);
    va_end(args);
    if (saved_errno != 0) {
        fprintf(stderr, "        errno: %s\n", strerror(saved_errno));
    }
    exit(exit_code);
}
