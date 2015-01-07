#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/if_flow.h>

#include <flow-table/data.h>

#include "flow-table-hairpind/ftbe.h"
#include "flow-table-hairpind/list.h"
#include "flow-table-hairpind/log.h"

struct ftbe_dummy_flow {
	struct list_head list;
	struct net_flow_flow flow;
};

/* A list will be very inefficient for large numbers of flows
 * but it seems sufficient for prototyping a dummy backend.
 */
static LIST_HEAD(ftbe_flows);

static int
ftbe_dummy_get_flows(int table, int min_prio, int max_prio,
		     int (*cb)(const struct net_flow_flow *flow, void *data),
		     void *cb_data)
{
	struct ftbe_dummy_flow *flow, *tmp;

	list_for_each_entry_safe(flow, tmp, &ftbe_flows, list) {
		if (table != flow->flow.table_id ||
		    (min_prio >= 0 && flow->flow.priority < min_prio) ||
		    (max_prio >= 0 && flow->flow.priority > max_prio))
			continue;
		if (cb(&flow->flow, cb_data))
			return -1;
	}

	return 0;
}

static int
ftbe_dummy_set_flow(const struct net_flow_flow *flow)
{
	struct ftbe_dummy_flow *f;

	/* XXX Verify table, header, match, actions, etc... are valid. */

	/* Return an error for a duplicate flow */
	list_for_each_entry(f, &ftbe_flows, list) {
		if (f->flow.table_id != flow->table_id)
			continue;
		if (f->flow.uid == flow->uid) {
			fthp_log_warn("Rejecting flow with duplicate uid\n");
			return -1;;
		}
		if (flow_table_field_refs_are_subset(f->flow.matches,
						     flow->matches)) {
			fthp_log_warn("Rejecting flow with duplicate match\n");
			return -1;;
		}
	}

	f = malloc(sizeof *f);
	if (!f)
		return -1;

	if (flow_table_flow_clone_data(&f->flow, flow)) {
		free(f);
		return -1;
	}

	INIT_LIST_HEAD(&f->list);
	list_add(&f->list, &ftbe_flows);

	return 0;
}

static void
__ftbe_dummy_del_flow(struct ftbe_dummy_flow *flow)
{
	list_del(&flow->list);
	flow_table_free_actions(flow->flow.actions);
	free(flow->flow.matches);
	free(flow);
}

static int ftbe_dummy_del_flow(const struct net_flow_flow *flow)
{
	struct ftbe_dummy_flow *f, *tmp;

	list_for_each_entry_safe(f, tmp, &ftbe_flows, list) {
		if (f->flow.table_id != flow->table_id)
			continue;
		if (!flow_table_field_refs_are_subset(f->flow.matches,
						      flow->matches))
			continue;
		__ftbe_dummy_del_flow(f);
	}

	return 0;
}

static void ftbe_dummy_destroy(void)
{
	struct ftbe_dummy_flow *f, *tmp;

	list_for_each_entry_safe(f, tmp, &ftbe_flows, list)
		__ftbe_dummy_del_flow(f);
}

static const struct ftbe_class ftbe_dummy = {
	.destroy	= ftbe_dummy_destroy,
	.get_flows	= ftbe_dummy_get_flows,
	.set_flow	= ftbe_dummy_set_flow,
	.del_flow	= ftbe_dummy_del_flow,
};

int ftbe_dummy_register(void) {
	return ftbe_register(&ftbe_dummy);
}
