#include <sys/types.h>
#include <sys/select.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <flow-table/msg.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#include <linux/if_flow.h>
#include <linux/if_flow_hairpin.h>

#include "flow-table-hairpind/log.h"
#include "flow-table-hairpind/msg.h"
#include "flow-table-hairpind/unused.h"

#define PROG_NAME "flow-table-hairpind"

#define MAX(a, b) (a > b ? a : b)

struct cb_priv {
	struct nl_sock *sock;
	int family;
};

static void
usage(void)
{
	fprintf(stderr, "Usage: " PROG_NAME "\n");
	exit(EXIT_FAILURE);
}

static void
set_listener(struct nl_sock *sock, int family)
{
	struct nl_msg *msg;
	int err;

	msg = fthp_put_msg_set_listener(family);
	if (!msg)
		fthp_log_fatal("could not put set listener message\n");

	err = nl_send_auto(sock, msg);
	if (err < 0)
		 fthp_log_fatal("error sending set listener message: %s\n",
				 nl_geterror(err));

	err = nl_recvmsgs_default(sock);
	if (err < 0)
		 fthp_log_fatal("error receiving set listener message: %s\n",
				 nl_geterror(err));

	free(msg);
}

static void
get_listener(struct nl_sock *sock, int family)
{
	int err;
	struct nl_msg *msg;

	msg = fthp_put_msg_get_listener(family);
	if (!msg)
		fthp_log_fatal("could not put get listener message\n");

	err = nl_send_auto(sock, msg);
	if (err < 0)
		 fthp_log_fatal("error sending get listener message: %s\n",
				 nl_geterror(err));

	err = nl_recvmsgs_default(sock);
	if (err < 0)
		 fthp_log_fatal("error receiving get listener message: %s\n",
				 nl_geterror(err));

	err = nl_recvmsgs_default(sock);
	if (err < 0)
		 fthp_log_fatal("error receiving get listener message: %s\n",
				 nl_geterror(err));

	free(msg);
}

static struct nla_policy net_flow_hairpin_listener_policy[NET_FLOW_HAIRPIN_MAX+1] =
{
	[NET_FLOW_HAIRPIN_LISTENER_ATTR_TYPE]	= { .type = NLA_U32 },
	[NET_FLOW_HAIRPIN_LISTENER_ATTR_PIDS]	= { .type = NLA_U32 },
};

static int listener_msg_handler(struct nlattr *attr)
{
	int err;
	struct nlattr *attrs[NET_FLOW_HAIRPIN_LISTENER_ATTR_MAX+1];
	uint32_t pid, type;

	if (!attr) {
		fthp_log_warn("missing listener attributes\n");
		return NL_SKIP;
	}

	err = nla_parse_nested(attrs, NET_FLOW_HAIRPIN_LISTENER_ATTR_MAX,
			       attr, net_flow_hairpin_listener_policy);
	if (err) {
		fthp_log_warn("could not parse listener attributes\n");
		return NL_SKIP;
	}

	if (!attrs[NET_FLOW_HAIRPIN_LISTENER_ATTR_TYPE] ||
	    !attrs[NET_FLOW_HAIRPIN_LISTENER_ATTR_PIDS]) {
		fthp_log_warn("missing listener attributes\n");
		return NL_SKIP;
	}

	type = nla_get_u32(attrs[NET_FLOW_HAIRPIN_LISTENER_ATTR_TYPE]);
	pid = nla_get_u32(attrs[NET_FLOW_HAIRPIN_LISTENER_ATTR_PIDS]);

	if (type != NET_FLOW_HAIRPIN_LISTENER_ATTR_TYPE_ENCAP) {
		fthp_log_warn("unknown listener type (%d) in message\n", type);
		return NL_SKIP;
	}

	printf("got listener: type=%u pids=%u\n", type, pid);

	return NL_OK;
}

static int net_flow_send_async_error(struct cb_priv *priv, uint32_t encap_cmd,
				     uint64_t seq, uint32_t status)
{
	int err;
	struct nl_msg *msg;

	fthp_log_warn("send async error: encap_cmd=%u seq=%lu status=%u\n",
		      encap_cmd, seq, status);

	msg = fthp_put_msg_async_error(priv->family, encap_cmd, seq, status);;
	if (!msg) {
		fthp_log_warn("%s: could not put async error message\n",
			      __func__);
		return NL_SKIP;
	}

	err = nl_send_auto(priv->sock, msg);
	free(msg);

	if (err < 0) {
		 fthp_log_warn("%s: error sending encap error message: %s\n",
			       nl_geterror(err));
		 return NL_SKIP;
	}

	return NL_OK;
}

static int encap_msg_handler__(struct cb_priv *priv,
			       uint64_t seq, int ifindex, uint32_t encap_cmd,
			       int (*cb)(struct nl_msg *msg, void *data),
			       void *cb_data)
{
	int err;
	struct nl_msg *msg;

	msg = fthp_put_msg_encap(priv->family, seq, ifindex, encap_cmd,
				 cb, cb_data);
	if (!msg) {
		fthp_log_warn("%s: error putting encap message\n", __func__);
		return NL_SKIP;
	}

	err = nl_send_auto(priv->sock, msg);

	free(msg);

	if (err < 0) {
		 fthp_log_warn("%s: error sending message: %s\n",
			       nl_geterror(err), __func__);
		 return NL_SKIP;
	}

	return NL_OK;
}

struct get_flows_cb_data {
	int table;
	int min_prio;
	int max_prio;
};

static int get_flows_cb__(struct nl_msg *UNUSED(msg), void *UNUSED(data))
{
	// XXX: Add flows here
	return 0;
}

static int get_flows_cb(struct nl_msg *msg, void *data)
{
	return flow_table_put_flows(msg, get_flows_cb__, data);
}

static int net_flow_get_flows_msg_handler(struct cb_priv *priv, uint64_t seq,
					  struct nlattr *attr)
{
	int ifindex;
	struct get_flows_cb_data cb_data;

	ifindex = flow_table_get_get_flows_request(attr, &cb_data.table,
						   &cb_data.max_prio,
						   &cb_data.min_prio);
	if (ifindex < 0) {
		fthp_log_warn("could not get 'get flows' request\n");
		return NL_SKIP;
	}

	return encap_msg_handler__(priv, seq, ifindex,
				   NET_FLOW_TABLE_CMD_GET_FLOWS,
				   get_flows_cb, &cb_data);
}

static int set_flows_cb(const struct net_flow_flow *UNUSED(flow),
			void *UNUSED(data))
{
	printf("%s\n", __func__);
	// XXX: Pass flows to lower layer here
	return 0;
}

static int net_flow_set_flows_msg_handler(struct cb_priv *priv, uint64_t seq,
					  struct nlattr *attr)
{
	int ifindex;

	ifindex = flow_table_get_set_flows_request(attr, set_flows_cb, NULL);
	if (ifindex < 0) {
		fthp_log_warn("could not get 'set flows' request\n");
		return NL_SKIP;
	}

	return encap_msg_handler__(priv, seq, ifindex,
				   NET_FLOW_TABLE_CMD_SET_FLOWS, NULL, NULL);
}

static int net_flow_msg_handler(struct cb_priv *priv, uint32_t cmd,
				uint64_t seq, struct nlattr *attr)
{
	int err;
	uint32_t err_status = NET_FLOW_HAIRPIN_ENCAP_STATUS_EINVAL;

	switch (cmd) {
	case NET_FLOW_TABLE_CMD_GET_FLOWS:
		err = net_flow_get_flows_msg_handler(priv, seq, attr);
		break;

	case NET_FLOW_TABLE_CMD_SET_FLOWS:
		err = net_flow_set_flows_msg_handler(priv, seq, attr);
		break;

	default:
		fthp_log_warn("unhandled encapsulated net flow message: "
			      "cmd=%u\n", cmd);
		err = NL_SKIP;
		err_status = NET_FLOW_HAIRPIN_ENCAP_STATUS_EOPNOTSUPP;
		break;
	}

	if (err != NL_OK)
		net_flow_send_async_error(priv, cmd, seq, err_status);

	return err;
}

static struct nla_policy net_flow_hairpin_encap_policy[NET_FLOW_HAIRPIN_ENCAP_MAX+1] =
{
	[NET_FLOW_HAIRPIN_ENCAP_CMD_TYPE]	= { .type = NLA_U32 },
	[NET_FLOW_HAIRPIN_ENCAP_CMD]		= { .type = NLA_U32 },
	[NET_FLOW_HAIRPIN_ENCAP_STATUS]		= { .type = NLA_U32 },
	[NET_FLOW_HAIRPIN_ENCAP_SEQ]		= { .type = NLA_U64 },
	[NET_FLOW_HAIRPIN_ENCAP_ATTR]		= { .type = NLA_NESTED },
};

static int encap_msg_handler(struct cb_priv *priv, struct nlattr *attr)
{
	int err;
	struct nlattr *attrs[NET_FLOW_HAIRPIN_ENCAP_MAX+1];
	uint32_t cmd, type;
	uint64_t seq;

	if (!attr) {
		fthp_log_warn("missing encap attributes\n");
		return NL_SKIP;
	}

	err = nla_parse_nested(attrs, NET_FLOW_HAIRPIN_ENCAP_MAX,
			       attr, net_flow_hairpin_encap_policy);
	if (err) {
		fthp_log_warn("could not parse encap attributes\n");
		return NL_SKIP;
	}

	if (!attrs[NET_FLOW_HAIRPIN_ENCAP_CMD_TYPE] ||
	    !attrs[NET_FLOW_HAIRPIN_ENCAP_CMD] ||
	    !attrs[NET_FLOW_HAIRPIN_ENCAP_SEQ] ||
	    !attrs[NET_FLOW_HAIRPIN_ENCAP_ATTR]) {
		fthp_log_warn("missing encap attributes\n");
		return NL_SKIP;
	}

	type = nla_get_u32(attrs[NET_FLOW_HAIRPIN_ENCAP_CMD_TYPE]);
	cmd = nla_get_u32(attrs[NET_FLOW_HAIRPIN_ENCAP_CMD]);
	seq = nla_get_u64(attrs[NET_FLOW_HAIRPIN_ENCAP_SEQ]);

	if (type != NET_FLOW_HAIRPIN_ENCAP_CMD_NET_FLOW_CMD) {
		net_flow_send_async_error(priv, cmd, seq,
					  NET_FLOW_HAIRPIN_ENCAP_STATUS_EOPNOTSUPP);
		fthp_log_warn("unknown encap cmd type (%d) in message\n", type);
		return NL_SKIP;
	}

	return net_flow_msg_handler(priv, cmd, seq,
				    attrs[NET_FLOW_HAIRPIN_ENCAP_ATTR]);
}

static struct nla_policy net_flow_hairpin_policy[NET_FLOW_HAIRPIN_MAX+1] =
{
	[NET_FLOW_HAIRPIN_ENCAP]	= { .type = NLA_NESTED },
	[NET_FLOW_HAIRPIN_LISTENER]	= { .type = NLA_NESTED },
};

static int
sync_handler(struct nl_msg *msg, void *UNUSED(arg))
{
	int err;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gehdr = genlmsg_hdr(hdr);
	struct nlattr *attrs[NET_FLOW_HAIRPIN_MAX+1];

	err = genlmsg_parse(hdr, 0, attrs, NET_FLOW_HAIRPIN_MAX,
			    net_flow_hairpin_policy);
	if (err) {
		fthp_log_warn("could not parse top level attributes\n");
		return NL_SKIP;
	}

	switch (gehdr->cmd) {
	case NET_FLOW_HAIRPIN_CMD_SET_LISTENER:
		fthp_log_warn("spurious NET_FLOW_HAIRPIN_CMD_SET_LISTENER "
			     "message\n");
		break;

	case NET_FLOW_HAIRPIN_CMD_GET_LISTENER:
		return listener_msg_handler(attrs[NET_FLOW_HAIRPIN_LISTENER]);

	case NET_FLOW_HAIRPIN_CMD_ENCAP:
		fthp_log_warn("spurious NET_FLOW_HAIRPIN_CMD_ENCAP message\n");
		break;

	default:
		fthp_log_warn("unknown command (%d) in message\n", gehdr->cmd);
		break;
	}

	return NL_SKIP;
}

static int
async_handler(struct nl_msg *msg, void *arg)
{
	int err;
	struct cb_priv *priv = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gehdr = genlmsg_hdr(hdr);
	struct nlattr *attrs[NET_FLOW_HAIRPIN_MAX+1];

	err = genlmsg_parse(hdr, 0, attrs, NET_FLOW_HAIRPIN_MAX,
			    net_flow_hairpin_policy);
	if (err) {
		fthp_log_warn("could not parse top level attributes\n");
		return NL_SKIP;
	}

	switch (gehdr->cmd) {
	case NET_FLOW_HAIRPIN_CMD_SET_LISTENER:
		fthp_log_warn("spurious NET_FLOW_HAIRPIN_CMD_SET_LISTENER "
			     "message\n");
		break;

	case NET_FLOW_HAIRPIN_CMD_GET_LISTENER:
		fthp_log_warn("spurious NET_FLOW_HAIRPIN_CMD_GET_LISTENER "
			     "message\n");
		break;

	case NET_FLOW_HAIRPIN_CMD_ENCAP:
		return encap_msg_handler(priv, attrs[NET_FLOW_HAIRPIN_ENCAP]);
		break;

	default:
		fthp_log_warn("unknown command (%d) in message\n", gehdr->cmd);
		break;
	}

	return NL_SKIP;
}

int
main(int argc, char **UNUSED(argv))
{
	int err, family;
	struct cb_priv priv;
	struct nl_sock *sync_sock = NULL;
	struct nl_sock *async_sock = NULL;

	if (argc != 1)
		usage();

	async_sock = nl_socket_alloc();
	sync_sock = nl_socket_alloc();
	if (!sync_sock || !async_sock)
		fthp_log_fatal("could not allocate netlink socket\n");

	err = nl_socket_modify_cb(sync_sock, NL_CB_VALID, NL_CB_CUSTOM,
				  sync_handler, NULL);
	if (err)
		fthp_log_fatal("error modifying callback: %s\n",
				nl_geterror(err));

	err = genl_connect(sync_sock);
	if (err < 0)
		fthp_log_fatal("could not connect to netlink socket: %s\n",
				nl_geterror(err));

	family = genl_ctrl_resolve(sync_sock, NET_FLOW_HAIRPIN_GENL_NAME);
	if (family < 0)
		fthp_log_fatal("error resolving generic netlink family \""
				NET_FLOW_HAIRPIN_GENL_NAME "\": %s\n",
				     nl_geterror(family));

	priv.family = family;
	priv.sock = sync_sock;
	err = nl_socket_modify_cb(async_sock, NL_CB_VALID, NL_CB_CUSTOM,
				  async_handler, &priv);
	if (err)
		fthp_log_fatal("error modifying callback: %s\n",
				nl_geterror(err));

	nl_socket_disable_seq_check(async_sock);
	err = genl_connect(async_sock);
	if (err < 0)
		fthp_log_fatal("could not connect to netlink socket: %s\n",
				nl_geterror(err));

	set_listener(sync_sock, family);
	get_listener(sync_sock, family);

	while (1) {
		int async_fd = nl_socket_get_fd(async_sock);
		int sync_fd = nl_socket_get_fd(sync_sock);
		int max_fd = MAX(async_fd, sync_fd);
		fd_set efds, rfds;

		FD_ZERO(&rfds);
		FD_SET(async_fd, &rfds);
		FD_SET(sync_fd, &rfds);

		FD_ZERO(&efds);
		FD_SET(async_fd, &efds);
		FD_SET(sync_fd, &efds);

		err = select(max_fd + 1, &rfds, NULL, &efds, NULL);
		if (errno == EINTR || !err)
			continue;

		if (err < 0)
			fthp_log_warn("error selecting netlink sockets: %s\n",
				      strerror(errno));

		if (FD_ISSET(async_fd, &rfds) || FD_ISSET(async_fd, &efds)) {
			err = nl_recvmsgs_default(async_sock);
			if (err < 0)
				fthp_log_warn("error receiving async message: "
					      "%s\n", nl_geterror(err));
		}

		if (FD_ISSET(sync_fd, &rfds) || FD_ISSET(sync_fd, &efds)) {
			err = nl_recvmsgs_default(sync_sock);
			if (err < 0)
				fthp_log_warn("error receiving sync message: "
					      "%s\n", nl_geterror(err));
		}
	}

	nl_socket_free(sync_sock);
	nl_socket_free(async_sock);

	return 0;
}
