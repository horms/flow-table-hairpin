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

#ifndef FTHP_MSG_H
#define FTHP_MSG_H

#include <netlink/msg.h>

struct nl_msg *fthp_put_msg_set_listener(int family);

struct nl_msg *fthp_put_msg_get_listener(int family);

struct nl_msg *
fthp_put_msg_encap(int family, uint64_t seq, int ifindex, uint32_t encap_cmd,
		   int (*cb)(struct nl_msg *msg, void *data), void *cb_data);

struct nl_msg *
fthp_put_msg_async_error(int family, uint32_t encap_cmd,
			 uint64_t seq, uint32_t status);
#endif
