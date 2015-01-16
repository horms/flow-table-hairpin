#ifndef FLOW_TABLE_LOG_H
#define FLOW_TABLE_LOG_H

void fthp_log_warn(const char *fmt, ...);
#define fthp_log_debug fthp_log_warn
void fthp_log_fatal(const char *fmt, ...);

#endif
