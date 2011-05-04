/*
 * NetworkTable.h
 *
 * Copyright 2001, 2003 by Anthony Howe.  All rights reserved.
 */

#ifndef __com_snert_mod_watch_NetworkTable_h__
#define __com_snert_mod_watch_NetworkTable_h__	1

#include <sys/types.h>
#include <netinet/in.h>

#include "httpd.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const char *ntAddNetwork(cmd_parms *cmd, apr_array_header_t *table, const char *network);
extern apr_ipsubnet_t *ntGetNetwork(apr_array_header_t *table, apr_sockaddr_t *sa);
extern int ntIsMember(apr_array_header_t *table, apr_sockaddr_t *sa);

#ifdef  __cplusplus
}
#endif

#endif /* __com_snert_mod_watch_NetworkTable_h__ */
