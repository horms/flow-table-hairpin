#include <sys/types.h>
#include <unistd.h>

#include <netlink/genl/genl.h>

#include <linux/if_flow.h>
#include <linux/if_flow_hairpin.h>

#include "flow-table-hairpind/log.h"
#include "flow-table-hairpind/msg.h"

static struct nl_msg *
fthp_msg_put(int family, int cmd)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			 0, 0, cmd, NET_FLOW_HAIRPIN_GENL_VERSION)) {
		free(msg);
		return NULL;
	}

	return msg;
}

struct nl_msg *
fthp_put_msg_set_listener(int family)
{
	struct nl_msg *msg;
	struct nlattr *start;

	msg = fthp_msg_put(family, NET_FLOW_HAIRPIN_CMD_SET_LISTENER);
	if (!msg)
		return NULL;

	start = nla_nest_start(msg, NET_FLOW_HAIRPIN_LISTENER);
	if (!start)
		goto err_msg;

	if (nla_put_u32(msg, NET_FLOW_HAIRPIN_LISTENER_ATTR_TYPE,
			NET_FLOW_HAIRPIN_LISTENER_ATTR_TYPE_ENCAP) ||
	    nla_put_u32(msg, NET_FLOW_HAIRPIN_LISTENER_ATTR_PIDS, getpid()))
		goto err_nest;

	nla_nest_end(msg, start);
	return msg;

err_nest:
	nla_nest_cancel(msg, start);
err_msg:
	free(msg);
	return NULL;
}

struct nl_msg *
fthp_put_msg_get_listener(int family)
{
	struct nl_msg *msg;
	struct nlattr *start;

	msg = fthp_msg_put(family, NET_FLOW_HAIRPIN_CMD_GET_LISTENER);
	if (!msg)
		return NULL;

	start = nla_nest_start(msg, NET_FLOW_HAIRPIN_LISTENER);
	if (!start)
		goto err_msg;

	if (nla_put_u32(msg, NET_FLOW_HAIRPIN_LISTENER_ATTR_TYPE,
			NET_FLOW_HAIRPIN_LISTENER_ATTR_TYPE_ENCAP))
		goto err_nest;

	nla_nest_end(msg, start);
	return msg;

err_nest:
	nla_nest_cancel(msg, start);
err_msg:
	free(msg);
	return NULL;
}

static int
fthp_put_encap_preamble(struct nl_msg *msg, uint32_t cmd,
			uint64_t seq, uint32_t status)
{
	if (nla_put_u32(msg, NET_FLOW_HAIRPIN_ENCAP_CMD_TYPE,
			NET_FLOW_HAIRPIN_ENCAP_CMD_NET_FLOW_CMD) ||
	    nla_put_u32(msg, NET_FLOW_HAIRPIN_ENCAP_CMD, cmd) ||
	    nla_put_u32(msg, NET_FLOW_HAIRPIN_ENCAP_STATUS, status) ||
	    nla_put_u64(msg, NET_FLOW_HAIRPIN_ENCAP_SEQ, seq))
		return -1;

	return 0;
}

struct nl_msg *
fthp_put_msg_encap(int family, uint64_t seq, int ifindex, uint32_t encap_cmd,
		   int (*cb)(struct nl_msg *msg, void *data), void *cb_data)
{
	struct nl_msg *msg;
	struct nlattr *encap, *encap_attr;

	msg = fthp_msg_put(family, NET_FLOW_HAIRPIN_CMD_ENCAP);

	encap = nla_nest_start(msg, NET_FLOW_HAIRPIN_ENCAP);
	if (!encap)
		goto err;

	if (fthp_put_encap_preamble(msg, encap_cmd, seq,
				    NET_FLOW_HAIRPIN_ENCAP_STATUS_OK))
		goto err_encap;

	encap_attr = nla_nest_start(msg, NET_FLOW_HAIRPIN_ENCAP_ATTR);
	if (!encap_attr)
		goto err_encap;

	if (nla_put_u32(msg, NET_FLOW_IDENTIFIER_TYPE,
			NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg, NET_FLOW_IDENTIFIER, ifindex))
		goto err_encap_attr;

	if (cb && cb(msg, cb_data))
		goto err_encap_attr;

	nla_nest_end(msg, encap_attr);
	nla_nest_end(msg, encap);

	return msg;

err_encap_attr:
	nla_nest_cancel(msg, encap_attr);
err_encap:
	nla_nest_cancel(msg, encap);
err:
	free(msg);
	return NULL;
}

struct nl_msg *
fthp_put_msg_async_error(int family, uint32_t encap_cmd,
			 uint64_t seq, uint32_t status)
{
	struct nl_msg *msg;
	struct nlattr *start;

	msg = fthp_msg_put(family, NET_FLOW_HAIRPIN_CMD_ENCAP);
	if (!msg)
		return NULL;

	start = nla_nest_start(msg, NET_FLOW_HAIRPIN_ENCAP);
	if (!start)
		goto err_msg;

	if (fthp_put_encap_preamble(msg, encap_cmd, seq, status))
		goto err_nest;

	nla_nest_end(msg, start);

	return msg;

err_nest:
	nla_nest_cancel(msg, start);
err_msg:
	free(msg);
	return NULL;
}
