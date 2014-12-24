#include <netlink/genl/genl.h>

#include <linux/if_flow_hairpin.h>

#include "flow-table-hairpind/log.h"
#include "flow-table-hairpind/msg.h"

struct nl_msg *
fthp_msg_put(int family, int cmd)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		fthp_log_fatal("Could not allocate netlink message\n");

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			 0, 0, cmd, NET_FLOW_HAIRPIN_GENL_VERSION))
		fthp_log_fatal("Could put netlink message\n");

	return msg;
}
