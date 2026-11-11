#ifndef NANOROCK_LOG_H
#define NANOROCK_LOG_H

/* Informational message, printed to stderr. */
void log_info(const char *fmt, ...);

/* Non-fatal problem: nanorock keeps going but the operator should know. */
void log_warn(const char *fmt, ...);

/* Something went wrong but we can still shut down cleanly. */
void log_error(const char *fmt, ...);

/* Diagnostic verbose message, printed only when verbose logging is enabled. */
void log_verbose(const char *fmt, ...);

/* Enable or disable verbose logging. */
void log_set_verbose(int enable);

/* Unrecoverable error: log it (including errno, if set) and exit(1). */
void die(const char *fmt, ...);

/* Unrecoverable error with specific exit code (e.g. usage error code 2, runtime error code 1). */
void die_with_code(int exit_code, const char *fmt, ...);

#endif /* NANOROCK_LOG_H */
