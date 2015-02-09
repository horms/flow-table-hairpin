/*
 * flow-table-hairpin: A flow table API offload driver user-space backend
 *
 * Copyright (C) 2015  Netronome.
 *
 * Contacts: Simon Horman <simon.horman@netronome.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

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
