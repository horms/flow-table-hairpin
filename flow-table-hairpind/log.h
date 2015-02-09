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

#ifndef FLOW_TABLE_LOG_H
#define FLOW_TABLE_LOG_H

void fthp_log_warn(const char *fmt, ...);
#define fthp_log_debug fthp_log_warn
#define fthp_log_err fthp_log_warn
void fthp_log_fatal(const char *fmt, ...);

#define BUG()								      \
do {									      \
	fthp_log_err("BUG at %s:%d in %s()\n", __FILE__, __LINE__, __func__); \
	abort();							      \
} while(0)
#endif
