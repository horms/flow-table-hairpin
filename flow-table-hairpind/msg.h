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
