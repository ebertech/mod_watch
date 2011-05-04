/*
 * NetworkTable.c
 *
 * Copyright 2001, 2003 by Anthony Howe.  All rights reserved.
 */

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#include "httpd.h"
#include "http_config.h"

#include "apr_portable.h"
#include "apr_strings.h"

#include "NetworkTable.h"

const char *
ntAddNetwork(cmd_parms *cmd, apr_array_header_t *table, const char *network)
{
	char *copy, *slash;
	apr_ipsubnet_t *subnet, **entry;

	if ((copy = apr_pstrdup(cmd->temp_pool, network)) == (char *) 0)
		return "Failed to add IP/mask to network table.";

	if ((slash = strchr(copy, '/')) != (char *) 0)
		*slash++ = '\0';

	switch (apr_ipsubnet_create(&subnet, copy, slash, cmd->pool)) {
	case APR_SUCCESS:
		entry = (apr_ipsubnet_t **) apr_array_push(table);
		if (entry == (apr_ipsubnet_t **) 0)
			return "Failed to add IP/mask to network table.";

		*entry = subnet;
		break;
	case APR_EBADMASK:
		return "Invalid network mask.";
	default:
		return "Invalid network specifier.";
	}

	return (char *) 0;
}

/*
 * Linear search of an array for the first matching subnet.
 */
apr_ipsubnet_t *
ntGetNetwork(apr_array_header_t *table, apr_sockaddr_t *sa)
{
	int i;
	apr_ipsubnet_t **array;

	if (table == (apr_array_header_t *) 0)
		return (apr_ipsubnet_t *) 0;

	array = (apr_ipsubnet_t **) table->elts;

	for (i = 0; i < table->nelts; ++i) {
		if (apr_ipsubnet_test(array[i], sa))
			return array[i];
	}

	return (apr_ipsubnet_t *) 0;
}

int
ntIsMember(apr_array_header_t *table, apr_sockaddr_t *sa)
{
	return ntGetNetwork(table, sa) != (apr_ipsubnet_t *) 0;
}

