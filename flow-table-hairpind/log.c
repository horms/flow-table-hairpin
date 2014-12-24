#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static void
fthp_vlog(const char *fmt, va_list ap)
{
	vfprintf(stderr, fmt, ap);
}

void
fthp_log_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fthp_vlog(fmt, ap);
	va_end(ap);
}

void
fthp_log_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fthp_vlog(fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}
