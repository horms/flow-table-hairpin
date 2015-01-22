#include <sys/types.h>
#include <sys/select.h>

#include <errno.h>
#include <getopt.h>
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

#include <flow-table/json.h>

#include "flow-table-hairpind/ftbe.h"
#include "flow-table-hairpind/ftbe-dummy.h"
#include "flow-table-hairpind/log.h"
#include "flow-table-hairpind/msg.h"
#include "flow-table-hairpind/unused.h"

#define PROG_NAME "flow-table-hairpind"

#define MAX(a, b) (a > b ? a : b)

struct config {
	struct json_object *tables;
	struct json_object *headers;
	struct json_object *actions;
	struct json_object *header_graph;
};

struct cb_priv {
	struct nl_sock *sock;
	int family;
	struct config config;
};

static void
usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " options\n"
		"\n"
		"options:\n"
		"  --tables FILENAME   (required)\n"
		"  --headers FILENAME  (required)\n"
		"  --actions FILENAME  (required)\n"
		"  --header-graph FILENAME  (required)\n");
	exit(EXIT_FAILURE);
}

static json_object *
load_json(const char *filename, const char *type)
{
	struct json_object *jobj;

	jobj = json_object_from_file(filename);
	if (!jobj)
		fthp_log_fatal("error parsing %s from file \'%s\'\n",
			       type, filename);

	if (!flow_table_json_check_type(jobj, type))
		fthp_log_fatal("error %s loaded from \'%s\' "
			       "do not appear to be %s\n",
			       type, filename, type);

	printf("%s\n%s\n", type,
	       json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY));
	return jobj;
}

static void
parse_cmdline(int argc, char * const *argv, struct config *config)
{
	memset (config, 0, sizeof *config);

	while (1) {
		int c, option_index = 0;

		static const struct option long_options[] = {
			{"tables",	required_argument,	0, 0 },
			{"headers",	required_argument,	0, 0 },
			{"actions",	required_argument,	0, 0 },
			{"header-graph", required_argument,	0, 0 },
			{0,         	0,			0, 0 }
		};

		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			switch (option_index) {
			case 0:
				if (config->tables) {
					fthp_log_err("Duplicate command line "
						     "argument --tables\n");
					usage();
				}
				config->tables = load_json(optarg, "tables");
				break;
			case 1:
				if (config->headers) {
					fthp_log_err("Duplicate command line "
						     "argument --headers\n");
					usage();
				}
				config->headers = load_json(optarg, "headers");
				break;
			case 2:
				if (config->actions) {
					fthp_log_err("Duplicate command line "
						     "argument --actions\n");
					usage();
				}
				config->actions = load_json(optarg, "actions");
				break;
			case 3:
				if (config->header_graph) {
					fthp_log_err("Duplicate command line "
						     "argument --header-graph\n");
					usage();
				}
				config->header_graph = load_json(optarg, "header_graph");
				break;
			default:
				BUG();
			}
			break;
		case '?':
			usage();
		default:
			BUG();
		}
	}

	if (!config->tables) {
		fthp_log_err("Missing --tables command line argument\n");
		usage();
	}
	if (!config->headers) {
		fthp_log_err("Missing --headers command line argument\n");
		usage();
	}
	if (!config->actions) {
		fthp_log_err("Missing --actions command line argument\n");
		usage();
	}
	if (!config->header_graph) {
		fthp_log_err("Missing --header-graph command line argument\n");
		usage();
	}

	return;
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

static struct nla_policy net_flow_hairpin_listener_policy[NFLH_MAX+1] =
{
	[NFLH_LISTENER_ATTR_TYPE]	= { .type = NLA_U32 },
	[NFLH_LISTENER_ATTR_PIDS]	= { .type = NLA_U32 },
};

static int listener_msg_handler(struct nlattr *attr)
{
	int err;
	struct nlattr *attrs[NFLH_LISTENER_ATTR_MAX+1];
	uint32_t pid, type;

	if (!attr) {
		fthp_log_warn("missing listener attributes\n");
		return NL_SKIP;
	}

	err = nla_parse_nested(attrs, NFLH_LISTENER_ATTR_MAX,
			       attr, net_flow_hairpin_listener_policy);
	if (err) {
		fthp_log_warn("could not parse listener attributes\n");
		return NL_SKIP;
	}

	if (!attrs[NFLH_LISTENER_ATTR_TYPE] ||
	    !attrs[NFLH_LISTENER_ATTR_PIDS]) {
		fthp_log_warn("missing listener attributes\n");
		return NL_SKIP;
	}

	type = nla_get_u32(attrs[NFLH_LISTENER_ATTR_TYPE]);
	pid = nla_get_u32(attrs[NFLH_LISTENER_ATTR_PIDS]);

	if (type != NFLH_LISTENER_ATTR_TYPE_ENCAP) {
		fthp_log_warn("unknown listener type (%d) in message\n", type);
		return NL_SKIP;
	}

	printf("got listener: type=%u pids=%u\n", type, pid);

	return NL_OK;
}

static const char *encap_cmd_name(uint32_t cmd)
{
	switch (cmd) {
	case NFL_TABLE_CMD_GET_TABLES:
		return "get tables";
	case NFL_TABLE_CMD_GET_HEADERS:
		return "get headers";
	case NFL_TABLE_CMD_GET_ACTIONS:
		return "get actions";
	case NFL_TABLE_CMD_GET_HDR_GRAPH:
		return "get header graph";
	case NFL_TABLE_CMD_GET_TABLE_GRAPH:
		return "get table graph";
	case NFL_TABLE_CMD_GET_FLOWS:
		return "get flows";
	case NFL_TABLE_CMD_SET_FLOWS:
		return "set flows";
	case NFL_TABLE_CMD_DEL_FLOWS:
		return "del flows";
	default:
		BUG();
	}
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

static int set_flows_cb(const struct net_flow_rule *flow, void *UNUSED(data))
{
	return ftbe_set_flow(flow);
}

static int net_flow_set_flows_msg_handler(struct cb_priv *priv, uint64_t seq,
					  struct nlattr *attr)
{
	int ifindex;

	ifindex = flow_table_flows_request(attr, set_flows_cb, NULL);
	if (ifindex < 0) {
		fthp_log_warn("could not get 'set flows' request\n");
		return NL_SKIP;
	}

	return encap_msg_handler__(priv, seq, ifindex,
				   NFL_TABLE_CMD_SET_FLOWS, NULL, NULL);
}

static int del_flows_cb(const struct net_flow_rule *rule, void *UNUSED(data))
{
	return ftbe_del_flow(rule);
}

static int net_flow_del_flows_msg_handler(struct cb_priv *priv, uint64_t seq,
					  struct nlattr *attr)
{
	int ifindex;

	ifindex = flow_table_flows_request(attr, del_flows_cb, NULL);
	if (ifindex < 0) {
		fthp_log_warn("could not get 'del flows' request\n");
		return NL_SKIP;
	}

	return encap_msg_handler__(priv, seq, ifindex,
				   NFL_TABLE_CMD_SET_FLOWS, NULL, NULL);
}

static int discovery_cb(struct nl_msg *msg, void *data)
{
	json_object *json = data;

	if (flow_table_json_to_nla(msg, json)) {
		fthp_log_warn("error putting tables\n");
		return -1;
	}

	return 0;
}

static int discovery_handler(struct cb_priv *priv, uint64_t seq,
			     uint32_t cmd, struct nlattr *attr,
			     json_object *data)
{
	int ifindex;
        int err;
        struct nl_msg *msg;

	ifindex = flow_table_get_ifindex_from_request(attr);
	if (ifindex < 0) {
		fthp_log_warn("could not get '%s' request\n",
			      encap_cmd_name(cmd));
		return NL_SKIP;
	}

        msg = fthp_put_msg_encap(priv->family, seq, ifindex, cmd,
				 discovery_cb, data);
	if (!msg)
		 fthp_log_fatal("error putting '%s' reply message\n",
				encap_cmd_name(cmd));

	err = nl_send_auto(priv->sock, msg);
	if (err < 0)
		 fthp_log_fatal("error sending '%s' reply: %s\n",
				encap_cmd_name(cmd), nl_geterror(err));

	return 0;
}

static int net_flow_msg_handler(struct cb_priv *priv, uint32_t cmd,
				uint64_t seq, struct nlattr *attr)
{
	int err;
	uint32_t err_status = NFLH_ENCAP_STATUS_EINVAL;

	switch (cmd) {
	case NFL_TABLE_CMD_SET_FLOWS:
		err = net_flow_set_flows_msg_handler(priv, seq, attr);
		break;

	case NFL_TABLE_CMD_DEL_FLOWS:
		err = net_flow_del_flows_msg_handler(priv, seq, attr);
		break;

	case NFL_TABLE_CMD_GET_TABLES:
		err = discovery_handler(priv, seq, NFL_TABLE_CMD_GET_TABLES,
					attr, priv->config.tables);
		break;

	case NFL_TABLE_CMD_GET_HEADERS:
		err = discovery_handler(priv, seq, NFL_TABLE_CMD_GET_HEADERS,
					attr, priv->config.headers);
		break;

	case NFL_TABLE_CMD_GET_ACTIONS:
		err = discovery_handler(priv, seq, NFL_TABLE_CMD_GET_ACTIONS,
					attr, priv->config.actions);
		break;

	case NFL_TABLE_CMD_GET_HDR_GRAPH:
		err = discovery_handler(priv, seq, NFL_TABLE_CMD_GET_HDR_GRAPH,
					attr, priv->config.header_graph);
		break;

	default:
		fthp_log_warn("unhandled encapsulated net flow message: "
			      "cmd=%u\n", cmd);
		err = NL_SKIP;
		err_status = NFLH_ENCAP_STATUS_EOPNOTSUPP;
		break;
	}

	if (err != NL_OK)
		net_flow_send_async_error(priv, cmd, seq, err_status);

	return err;
}

static struct nla_policy net_flow_hairpin_encap_policy[NFLH_ENCAP_MAX+1] =
{
	[NFLH_ENCAP_CMD_TYPE]	= { .type = NLA_U32 },
	[NFLH_ENCAP_CMD]		= { .type = NLA_U32 },
	[NFLH_ENCAP_STATUS]		= { .type = NLA_U32 },
	[NFLH_ENCAP_SEQ]		= { .type = NLA_U64 },
	[NFLH_ENCAP_ATTR]		= { .type = NLA_NESTED },
};

static int encap_msg_handler(struct cb_priv *priv, struct nlattr *attr)
{
	int err;
	struct nlattr *attrs[NFLH_ENCAP_MAX+1];
	uint32_t cmd, type;
	uint64_t seq;

	if (!attr) {
		fthp_log_warn("missing encap attributes\n");
		return NL_SKIP;
	}

	err = nla_parse_nested(attrs, NFLH_ENCAP_MAX,
			       attr, net_flow_hairpin_encap_policy);
	if (err) {
		fthp_log_warn("could not parse encap attributes\n");
		return NL_SKIP;
	}

	if (!attrs[NFLH_ENCAP_CMD_TYPE] ||
	    !attrs[NFLH_ENCAP_CMD] ||
	    !attrs[NFLH_ENCAP_SEQ] ||
	    !attrs[NFLH_ENCAP_ATTR]) {
		fthp_log_warn("missing encap attributes\n");
		return NL_SKIP;
	}

	type = nla_get_u32(attrs[NFLH_ENCAP_CMD_TYPE]);
	cmd = nla_get_u32(attrs[NFLH_ENCAP_CMD]);
	seq = nla_get_u64(attrs[NFLH_ENCAP_SEQ]);

	if (type != NFLH_ENCAP_CMD_NFL_CMD) {
		net_flow_send_async_error(priv, cmd, seq,
					  NFLH_ENCAP_STATUS_EOPNOTSUPP);
		fthp_log_warn("unknown encap cmd type (%d) in message\n", type);
		return NL_SKIP;
	}

	return net_flow_msg_handler(priv, cmd, seq,
				    attrs[NFLH_ENCAP_ATTR]);
}

static struct nla_policy net_flow_hairpin_policy[NFLH_MAX+1] =
{
	[NFLH_ENCAP]	= { .type = NLA_NESTED },
	[NFLH_LISTENER]	= { .type = NLA_NESTED },
};

static int
sync_handler(struct nl_msg *msg, void *UNUSED(arg))
{
	int err;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gehdr = genlmsg_hdr(hdr);
	struct nlattr *attrs[NFLH_MAX+1];

	err = genlmsg_parse(hdr, 0, attrs, NFLH_MAX,
			    net_flow_hairpin_policy);
	if (err) {
		fthp_log_warn("could not parse top level attributes\n");
		return NL_SKIP;
	}

	switch (gehdr->cmd) {
	case NFLH_CMD_SET_LISTENER:
		fthp_log_warn("spurious NFLH_CMD_SET_LISTENER "
			     "message\n");
		break;

	case NFLH_CMD_GET_LISTENER:
		return listener_msg_handler(attrs[NFLH_LISTENER]);

	case NFLH_CMD_ENCAP:
		fthp_log_warn("spurious NFLH_CMD_ENCAP message\n");
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
	struct nlattr *attrs[NFLH_MAX+1];

	err = genlmsg_parse(hdr, 0, attrs, NFLH_MAX,
			    net_flow_hairpin_policy);
	if (err) {
		fthp_log_warn("could not parse top level attributes\n");
		return NL_SKIP;
	}

	switch (gehdr->cmd) {
	case NFLH_CMD_SET_LISTENER:
		fthp_log_warn("spurious NFLH_CMD_SET_LISTENER message\n");
		break;

	case NFLH_CMD_GET_LISTENER:
		fthp_log_warn("spurious NFLH_CMD_GET_LISTENER message\n");
		break;

	case NFLH_CMD_ENCAP:
		return encap_msg_handler(priv, attrs[NFLH_ENCAP]);
		break;

	default:
		fthp_log_warn("unknown command (%d) in message\n", gehdr->cmd);
		break;
	}

	return NL_SKIP;
}

int
main(int argc, char **argv)
{
	int err, family;
	struct cb_priv priv;
	struct nl_sock *sync_sock = NULL;
	struct nl_sock *async_sock = NULL;

	parse_cmdline(argc, argv, &priv.config);

	if (ftbe_dummy_register())
		fthp_log_fatal("could not register dummy flow table "
			       "back end\n");

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

	family = genl_ctrl_resolve(sync_sock, NFLH_GENL_NAME);
	if (family < 0)
		fthp_log_fatal("error resolving generic netlink family \""
				NFLH_GENL_NAME "\": %s\n",
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
	ftbe_unregister();

	return 0;
}
