#ifndef FTHPD_FTBE_H
#define FTHPD_FTBE_H

#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>

#include <linux/if_flow.h>

#include <flow-table/types.h>

extern const struct ftbe_class *ftbe;

struct ftbe_class {
	int (*init)(void);
	void (*destroy)(void);

	int (*get_flows)(int table, int min_prio, int max_prio,
			 int (*cb)(const struct net_flow_flow *flow,
				   void *data),
			 void *cb_data);
	int (*set_flow)(const struct net_flow_flow *flow);
	int (*del_flow)(const struct net_flow_flow *flow);
};

static inline int
ftbe_init(void)
{
	if (!ftbe)
		return -1;
	if (!ftbe->init)
		return 0;
	return ftbe->init();
}

static inline void
ftbe_destroy(void)
{
	if (ftbe && ftbe->destroy)
		ftbe->destroy();
}

static inline int
ftbe_get_flows(int table, int min_prio, int max_prio,
	       int (*cb)(const struct net_flow_flow *flow, void *data),
	       void *cb_data)
{
	if (!ftbe || !ftbe->get_flows || !cb)
		return -1;
	return ftbe->get_flows(table, min_prio, max_prio, cb, cb_data);
}

static inline int
ftbe_set_flow(const struct net_flow_flow *flow)
{
	if (!ftbe || !ftbe->set_flow)
		return -1;
	return ftbe->set_flow(flow);
}

static inline int
ftbe_del_flow(const struct net_flow_flow *flow)
{
	if (!ftbe || !ftbe->del_flow)
		return -1;
	return ftbe->del_flow(flow);
}

static inline int
ftbe_register(const struct ftbe_class *cls)
{
	if (ftbe)
		return -1;
	ftbe = cls;

	return 0;
}

static inline void
ftbe_unregister(void)
{
	ftbe_destroy();
	ftbe = NULL;
}
#endif
