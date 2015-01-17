#ifndef FLOW_TABLE_LOG_H
#define FLOW_TABLE_LOG_H

void fthp_log_warn(const char *fmt, ...);
#define fthp_log_debug fthp_log_warn
#define fthp_log_err fthp_log_warn
void fthp_log_fatal(const char *fmt, ...);

#define BUG()								      \
do {									      \
	fthp_log_err("BUG at %s:%d in %s()\n", __FILE__, __LINE__, __func__); \
	abort();							      \
} while(0)
#endif
