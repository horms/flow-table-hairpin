#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/if_flow.h>

#include <flow-table/data.h>

#include "flow-table-hairpind/ftbe.h"
#include "flow-table-hairpind/list.h"
#include "flow-table-hairpind/log.h"

struct ftbe_dummy_rule {
	struct list_head list;
	struct net_flow_rule rule;
};

/* A list will be very inefficient for large numbers of rules
 * but it seems sufficient for prototyping a dummy backend.
 */
static LIST_HEAD(ftbe_rules);

static int
ftbe_dummy_get_flows(int table, int min_prio, int max_prio,
		     int (*cb)(const struct net_flow_rule *rule, void *data),
		     void *cb_data)
{
	struct ftbe_dummy_rule *rule, *tmp;

	list_for_each_entry_safe(rule, tmp, &ftbe_rules, list) {
		if (table != rule->rule.table_id ||
		    (min_prio >= 0 && rule->rule.priority < min_prio) ||
		    (max_prio >= 0 && rule->rule.priority > max_prio))
			continue;
		if (cb(&rule->rule, cb_data))
			return -1;
	}

	return 0;
}

static int
ftbe_dummy_set_flow(const struct net_flow_rule *rule)
{
	struct ftbe_dummy_rule *r;

	/* XXX Verify table, header, match, actions, etc... are valid. */

	/* Return an error for a duplicate rule */
	list_for_each_entry(r, &ftbe_rules, list) {
		if (r->rule.table_id != rule->table_id)
			continue;
		if (r->rule.uid == rule->uid) {
			fthp_log_warn("Rejecting rule for table %d with "
				      "duplicate uid %d\n", rule->table_id,
				      rule->uid);
			return -1;;
		}
		if (flow_table_field_refs_are_subset(r->rule.matches,
						     rule->matches)) {
			fthp_log_warn("Rejecting rule for table %d with "
				      "duplicate match. New rule's uid is %d. "
				      "Existing rule's uid is %d\n",
				      rule->table_id, rule->uid, r->rule.uid);
			return -1;;
		}
	}

	r = malloc(sizeof *r);
	if (!r)
		return -1;

	if (flow_table_rule_clone_data(&r->rule, rule)) {
		free(r);
		return -1;
	}

	INIT_LIST_HEAD(&r->list);
	list_add(&r->list, &ftbe_rules);

	return 0;
}

static void
__ftbe_dummy_del_rule(struct ftbe_dummy_rule *rule)
{
	list_del(&rule->list);
	flow_table_free_actions(rule->rule.actions);
	free(rule->rule.matches);
	free(rule);
}

static int ftbe_dummy_del_flow(const struct net_flow_rule *rule)
{
	struct ftbe_dummy_rule *r, *tmp;

	list_for_each_entry_safe(r, tmp, &ftbe_rules, list) {
		if (r->rule.table_id != rule->table_id)
			continue;
		if (!flow_table_field_refs_are_subset(r->rule.matches,
						      rule->matches))
			continue;
		__ftbe_dummy_del_rule(r);
	}

	return 0;
}

static void ftbe_dummy_destroy(void)
{
	struct ftbe_dummy_rule *f, *tmp;

	list_for_each_entry_safe(f, tmp, &ftbe_rules, list)
		__ftbe_dummy_del_rule(f);
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
