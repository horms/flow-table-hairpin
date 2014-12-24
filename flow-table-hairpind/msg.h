#ifndef FLOW_TABLE_MSG_H
#define FLOW_TABLE_MSG_H

#include <netlink/msg.h>

struct nl_msg * fthp_msg_put(int family, int cmd);

#endif
