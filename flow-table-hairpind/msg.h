#ifndef FTHP_MSG_H
#define FTHP_MSG_H

#include <netlink/msg.h>

struct nl_msg * fthp_msg_put(int family, int cmd);

#endif
