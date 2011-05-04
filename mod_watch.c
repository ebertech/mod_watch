/*
 * mod_watch.c for Apache 2
 *
 * Copyright 2001, 2003 by Anthony Howe.  All rights reserved.
 *
 * Please refer to LICENSE.TXT for the License & Disclaimer. An
 * online copy of the current license for the current version can
 * be found at http://www.snert.com/Software/mod_watch/
 */

#ifndef STATEDIR
#define STATEDIR		"/var/lib/mod_watch/"
#endif

/*
 * The size of the hash table should be a small prime number:
 *
 *	449, 673, 991, 1409, 2411
 *
 * Using a prime number for the table size means that double
 * hashing or linear-probing can visit all possible entries.
 *
 * This is NOT a runtime option, because its not something I
 * want people to play with unless absolutely necessary.
 */
#ifndef TABLE_SIZE
#define TABLE_SIZE		991
#endif

/*
 * The minimum amount of time in seconds between average rate
 * calculations.
 */
#ifndef SECONDS_PER_PERIOD
#define SECONDS_PER_PERIOD	300
#endif

/*
 * I'm concerned that a denial-of-service attack could be conducted
 * by flooding the server with a series of requests with large and
 * falsified Content-Length headers. The ap_discard_request_body()
 * does set a timeout when this function is used, but is rather long
 * IMHO. However, reading the comments for ap_discard_request_body(),
 * its use makes sense, but I think could be abused. There must be
 * another way.
 */
#define DISCARD_REQUEST_BODY 	1

#ifndef MAX_NUMBER_LENGTH
#define MAX_NUMBER_LENGTH	50
#endif


#undef WATCH_INPUT_VERSION_3
#undef WATCH_OUTPUT_VERSION_3

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#define MODULE		"mod_watch"
#define AUTHOR		"achowe@snert.com"
#define VERSION		"4.3"
#define COPYRIGHT	"Copyright 2001, 2003 by Anthony Howe. All rights reserved."
#define LICENSE_URL	"http://www.snert.com/Software/mod_watch/index.shtml#License"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"

#if defined(__unix__)
/* There MUST be a better way to do this with the APR, but I
 * have't found it due to the crappy documentation they've
 * provided developers, so that means: Use the Source Luke.
 */
#include "unixd.h"
#endif

module AP_MODULE_DECLARE_DATA watch_module;

/* This is NOT static for a reason so that it can
 * be used for error reporting else where.
 */
server_rec *watchMainServer;

/***********************************************************************
 *** Macros
 ***********************************************************************/

#define UNSET			-1
#define MERGE(p, c)		(c == UNSET ? p : c)
#define MERGE_PTR(p, c)		((void *) c == (void *) 0 ? p : c)

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define WATCH_SERVER			1
#define WATCH_SERVER_BY_PORT		2

#define WATCH_VHOST			4
#define WATCH_VHOST_BY_PORT		8

#define WATCH_OWNER			16
#define WATCH_OWNER_BY_PORT		32

#define WATCH_REMOTE_IP			64
#define WATCH_REMOTE_IP_BY_PORT		128

#define WATCH_HEADERS_IN		256
#define WATCH_HEADERS_OUT		512
#define WATCH_CONTENT_LENGTH		1024

#define WATCH_DEFAULT			32768
#define WATCH_ALL			(~0)

#define WATCH_INFO			1
#define WATCH_LIST			2
#define WATCH_TABLE			4
#define WATCH_FLUSH			8

/***********************************************************************
 *** String Constants
 ***********************************************************************/

static const char SERVER[] = "SERVER";
static const char LOCKFILE[] = "mod_watch.lock";
static const char ISHANDLER[] = "watch-is-handler";
static const char STARTTIME[] = "watch-start-time";

static const char watch_all[] = "all";
static const char watch_default[] = "default";
static const char watch_flush[] = "watch-flush";
static const char watch_info[] = "watch-info";
static const char watch_list[] = "watch-list";
static const char watch_table[] = "watch-table";
static const char watch_io[] = "watch-io";

static const char text_plain[] = "text/plain";
static const char text_html[] = "text/html";

/***********************************************************************
 *** Global variables - should be read-only by child processes.
 ***********************************************************************/

typedef struct watchConfDir {
	int index;
} watchConfDir;

typedef struct watchConnectionIO {
	unsigned long octetsIn;
	unsigned long octetsOut;
} watchConnectionIO;

static int watch_what;
static int watch_log_all;
static int watchDynamicVirtualHost;
static apr_time_t watchRestartTime;

static char *stateDirectory;
static apr_array_header_t *watchStateFileList;
static apr_array_header_t *watchDocumentsList;

static const char *watchDocumentsDef[] = {
	text_html,
	text_plain,
	"text/xml",
	"application/pdf",
	"text/enriched",
	"text/richtext",
	"application/*word",
	"application/*excel",
	"application/postscript",
	"application/rtf",
/*	"httpd/unix-directory", */
	(char *) 0
};

/***********************************************************************
 *** Shared Memory Hash Table Routines
 ***********************************************************************/

#include "SharedHash.h"

static int shTableSize;
static struct shTable *shtable;

/***********************************************************************
 *** Network Table Routines
 ***********************************************************************/

#include "NetworkTable.h"

static apr_array_header_t *networkIncludeList;
static apr_array_header_t *networkExcludeList;

/***********************************************************************
 *** Support Routines
 ***********************************************************************/

typedef void (*watch_print_entry)(request_rec *, struct shEntry *, int);

#define UNKNOWN_UID		((uid_t) ~0)
#define UNKNOWN_GID		((gid_t) ~0)

static int
ml_istrue(const char *s)
{
	if (ap_strcasecmp_match(s, "enable") == 0)	/* disable */
		return 1;
	if (ap_strcasecmp_match(s, "true") == 0)	/* false */
		return 1;
	if (ap_strcasecmp_match(s, "yes") == 0)		/* no */
		return 1;
	if (ap_strcasecmp_match(s, "on") == 0)		/* off */
		return 1;
	if (ap_strcasecmp_match(s, "1") == 0)		/* 0 */
		return 1;

	return 0;
}

int
ml_isfalse(const char *s)
{
	if (ap_strcasecmp_match(s, "disable") == 0)	/* enable */
		return 1;
	if (ap_strcasecmp_match(s, "false") == 0)	/* true */
		return 1;
	if (ap_strcasecmp_match(s, "no") == 0)		/* yes */
		return 1;
	if (ap_strcasecmp_match(s, "off") == 0)		/* off */
		return 1;
	if (ap_strcasecmp_match(s, "0") == 0)		/* 0 */
		return 1;

	return 0;
}

/*
 */
static const char *
userGetName(apr_pool_t *p, apr_uid_t uid)
{
	if (uid == UNKNOWN_UID)
		return "unknown-user";

#ifndef APR_HAS_USER
	return "default-user";
#else
{
	char *username;

//	if (apr_get_username(&username, uid, p) == APR_SUCCESS)
	if (apr_uid_name_get(&username, uid, p) == APR_SUCCESS)
		return username;

	return "unknown-user";
}
#endif
}

const char *
groupGetName(apr_pool_t *p, apr_gid_t gid)
{
	if (gid == UNKNOWN_GID)
		return "unknown-group";

#ifndef APR_HAS_USER
	return "default-group";
#else
{
	char *groupname;

	if (apr_gid_name_get(&groupname, gid, p) == APR_SUCCESS)
		return groupname;

	return "unknown-group";
}
#endif
}

static const char *
setDirectory(apr_pool_t *p, const char *arg, char **directory)
{
        arg = ap_server_root_relative(p, arg);

	/* Append trailing slash. */
	if (strrchr(arg, '/')[1] != '\0')
		*directory = apr_pstrcat(p, arg, "/", (char *) 0);
	else
		*directory = apr_pstrdup(p, arg);

	return (const char *) 0;
}

static const char *
setUnsignedInt(const char *arg, unsigned int *number)
{
	char *stop;
	long value;

	if (arg == (char *) 0 || *arg == '\0')
		return "Integer unspecified";

	value = strtol(arg, &stop, 10);

	if (*stop != '\0')
		return "Not a decimal integer";

	if (value < 0)
		return "Not a positive integer";

	if (UINT_MAX < value)
		return "Integer too large";

	*number = (unsigned int) value;

	return (const char *) 0;
}

static APR_DECLARE(apr_status_t)
fileReadWord(apr_file_t *fp, char *buf, apr_size_t *nbytes)
{
	char byte, *start, *stop;
	apr_status_t rc = APR_SUCCESS;

	for (start = buf, stop = buf + *nbytes - 1; buf < stop; buf++) {
		if ((rc = apr_file_getc(buf, fp)) != APR_SUCCESS)
			break;

		if (apr_isspace(*buf))
			break;
	}

	*nbytes = buf - start;
	*buf = '\0';

	return rc;

}

static APR_DECLARE(apr_status_t)
fileReadFormat(apr_file_t *fp, void *number, const char *format)
{
	int rc;
	apr_size_t nbytes;
	char word[MAX_NUMBER_LENGTH], *stop;

	nbytes = sizeof word;
	rc = fileReadWord(fp, word, &nbytes);
//	if (!APR_STATUS_IS_SUCCESS(rc))
	if (rc != APR_SUCCESS)
		return rc;

	return sscanf(word, format, number) == 1 ? APR_SUCCESS : APR_EGENERAL;
}

static APR_DECLARE(apr_status_t)
fileReadDouble(apr_file_t *fp, double *number)
{
	int rc;
	apr_size_t nbytes;
	char word[MAX_NUMBER_LENGTH];

	nbytes = sizeof word;
	rc = fileReadWord(fp, word, &nbytes);
//	if (!APR_STATUS_IS_SUCCESS(rc))
	if (rc != APR_SUCCESS )
		return rc;

	return sscanf(word, "%lf", number) == 1 ? APR_SUCCESS : APR_EGENERAL;
}

/*
 * Return the canonical name of the virtual host.
 *
 * The ap_get_server_name() returns either the defined ServerName
 * or the client supplied host name depending on the setting of
 * UseCanonicalName. When UseCanonicalName is on, only the virtual
 * host's ServerName is ever returned. When UseCanonicalName is off
 * the host name from a proxy URI or Host: header will be returned,
 * in which case there may be several different names per server.
 *
 * We always want to use the canonical name of a server when available,
 * regardless of the setting of UseCanonicalName or the presence of
 * mod_vhost_alias, so that we only track the "one true name".
 */
static char *
watchGetCanonicalName(request_rec *r)
{
	int i;
	char **list;
	apr_array_header_t *names;

	if (r->hostname == (char *) 0)
		return (char *) 0;

	/* Does request host name match the ServerName? */
	if (strcasecmp(r->hostname, r->server->server_hostname) == 0)
		return r->server->server_hostname;

	/* Does request host name match a ServerAlias for a <VirtualHost>. */
	names = r->server->names;
	if (names != (apr_array_header_t *) 0) {
		list = (char **) names->elts;
		for (i = 0; i < names->nelts; ++i) {
			if (list[i] != (char *) 0 && strcasecmp(r->hostname, list[i]) == 0)
				return r->server->server_hostname;
		}
	}

	names = r->server->wild_names;
	if (names != (apr_array_header_t *) 0) {
		list = (char **) names->elts;
		for (i = 0; i < names->nelts; ++i) {
			if (list[i] != (char *) 0 && ap_strcasecmp_match(r->hostname, list[i]) == 0)
				return r->server->server_hostname;
		}
	}

	if (watchDynamicVirtualHost) {
		/* The client supplied host name does not correspond to a
		 * declared name or alias for this server. See if a simple
		 * sub-request for the host name in question would succeed,
		 * in which case the client supplied host name is good.
		 */
		int exists;
		request_rec *sub;

		sub = ap_sub_req_method_uri("HEAD", "/", r, (ap_filter_t *) 0);
		exists = sub->finfo.filetype != APR_NOFILE;
		ap_destroy_sub_req(sub);

		ap_log_error(
			APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, watchMainServer,
			"watchGetCanonicalName(%lx) host=\"%s\" exits=%d",
			r, r->hostname, exists
		);

		if (exists) {
			ap_str_tolower((char *) r->hostname);
			return (char *) r->hostname;
		}
	}

	/* The client supplied host name does not correspond to ANYTHING.
	 * Do NOT log the results of this request by virtual host, since
	 * we cannot determine the host name.
	 */

	return (char *) 0;
}

static int
watchHeaderLength(void *data, const char *key, const char *value)
{
	unsigned long *octets = (unsigned long *) data;

	/* Count length of the header plus account for a colon,
	 * space, and CRLF.
	 */
	*octets += strlen(key) + strlen(value) + 4;

	return 1;
}

static struct shEntry *
watchCounters(request_rec *r)
{
	struct shEntry *data;
	watchConnectionIO *wc;
	const char *value, *gzip;
	unsigned long content_length, hdr_out;

	wc = ap_get_module_config(r->connection->conn_config, &watch_module);

	data = apr_palloc(r->pool, sizeof *data);
	data->key = (char *) 0;
	data->ifInOctets = 0;

#ifdef WATCH_INPUT_VERSION_3
	if (watch_what & WATCH_HEADERS_IN) {
		/* Count the request plus CRLF. */
		data->ifInOctets = strlen(r->the_request) + 2;
		apr_table_do(watchHeaderLength, &data->ifInOctets, r->headers_in, (char *) 0);
	}

	if ((watch_what & WATCH_CONTENT_LENGTH) && r->method_number == M_POST) {
		/* Assume content-length input bytes were consumed
		 * by a module or CGI. There is no way to guarantee
		 * that these bytes were actually sent and read -
		 * someone could easily falsify the headers by hand
		 * just to spike the graph.
		 */
		value = apr_table_get(r->headers_in, "Content-Length");
		if (value != (const char *) 0)
			data->ifInOctets += strtol(value, (char **) 0, 10);
	}
#else
	data->ifInOctets = wc->octetsIn;

	/* A connection can process more than one request, so reset. */
	wc->octetsIn = 0;
#endif

#ifdef WATCH_OUTPUT_VERSION_3
	hdr_out = 0;
	if (watch_what & WATCH_HEADERS_OUT)
		apr_table_do(watchHeaderLength, &hdr_out, r->headers_out, (char *) 0);

	/* Size of response sent. */
	data->ifOutOctets = hdr_out + r->bytes_sent;

	/* Check for mod_gzip and use the compressed output size. */
 	gzip = apr_table_get(r->notes, "mod_gzip_output_size");
 	if (gzip != (const char *) 0) {
 		unsigned long size = (unsigned long) strtol(gzip, (char **) 0, 10);
		data->ifOutOctets = hdr_out + (0 < size ? size : r->bytes_sent);
	}

	ap_log_error(
		APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, watchMainServer,
		"watchCounters(r=%lx) r->bytes_sent=%lu, mod_gzip_output_size=%s",
		(unsigned long) r, r->bytes_sent, gzip == (const char *) 0 ? "undefined" : gzip
	);
#else
	data->ifOutOctets = wc->octetsOut;

	/* A connection can process more than one request, so reset. */
	wc->octetsOut = 0;
#endif

	data->ifRequests = 1;
	data->ifDocuments = 0;
	data->ifOutRate = 0;	/* not used, filler */
	data->ifActive = 1;	/* not used, filler */

	/* Update ifDocuments counter. */
	if (r->content_type != (const char *) 0) {
		int i;
		request_rec *rr;
		char **list = (char **) watchDocumentsList->elts;

		/* Find actual content handler issued. */
		for (rr = r; rr->next != (request_rec *) 0; rr = rr->next)
			;

		for (i = 0; i < watchDocumentsList->nelts; ++i) {
			if (ap_strcasecmp_match(rr->content_type, list[i]) == 0) {
				data->ifDocuments = 1;
				break;
			}
		}
	}

	return data;
}

/*
 * Pick a target, which is either the server name of the request
 * or a specified ~user name or ~SERVER.
 */
static const char *
watchTarget(request_rec *r)
{
	if (r->uri[0] == '/' && r->uri[1] == '~' && apr_isalnum(r->uri[2])) {
		char *stop = ap_strcasestr(r->uri, "/watch-info");
		return apr_pstrmemdup(r->pool, r->uri + 2, stop - (r->uri + 2));
	}

	return watchGetCanonicalName(r);
}

/***********************************************************************
 ***  Filter handlers
 ***********************************************************************/

static apr_status_t
watchFilterInput(
	ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode,
	apr_read_type_e block, apr_off_t readbytes
)
{
	apr_status_t rc;
	apr_off_t length;
	watchConnectionIO *wc;

	wc = ap_get_module_config(f->c->conn_config, &watch_module);
	rc = ap_get_brigade(f->next, bb, mode, block, readbytes);
	apr_brigade_length(bb, 0, &length);

	if (0 < length)
		wc->octetsIn += length;

	return rc;
}

static apr_status_t
watchFilterOutput(ap_filter_t *f, apr_bucket_brigade *bb)
{
	apr_off_t length;
	watchConnectionIO *wc;

	wc = ap_get_module_config(f->c->conn_config, &watch_module);
	apr_brigade_length(bb, 0, &length);

	if (0 < length)
		wc->octetsOut += length;

	return ap_pass_brigade(f->next, bb);
}

/***********************************************************************
 ***  Phase handlers
 ***********************************************************************/

static int
watchPreConnection(conn_rec *c, void *csd)
{
	watchConnectionIO *wc = apr_pcalloc(c->pool, sizeof (*wc));

	ap_set_module_config(c->conn_config, &watch_module, wc);
	ap_add_output_filter(watch_io, NULL, NULL, c);
	ap_add_input_filter(watch_io, NULL, NULL, c);

	return OK;
}

static apr_status_t
watchCleanUpHash(void *data)
{
	char *prefix;
	char *name = (char *) data;
	struct shEntry *entry = shGetLockedEntry(shtable, name);

	if (entry == (struct shEntry *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"shGetLockedEntry(%lx, \"%s\") failed in watchCleanUpHash()",
			(unsigned long) shtable, name
		);
		return APR_EGENERAL;
	}

	if (--entry->ifActive < 0) {
		ap_log_error(
			APLOG_MARK, APLOG_WARNING, APR_SUCCESS, watchMainServer,
			"\"%s\" concurrency counter went negative; resetting to zero",
			name
		);
		entry->ifActive = 0;
	}

	ap_log_error(
		APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, watchMainServer,
		"watchCleanUpHash(%lx) key=%s active=%d",
		data, entry->key, entry->ifActive
	);

	if (shUnlock(shtable)) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"shUnlock(%lx) failed in watchCleanUpHash()",
			(unsigned long) shtable
		);
	}

	return APR_SUCCESS;
}

static void
watchPostReadRequestHash(request_rec *r, const char *keyNotes, const char *keyHash)
{
	struct shEntry *copy, *entry;

	if (keyHash == (char *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_INFO, APR_SUCCESS, watchMainServer,
			"counters not loaded, bogus hostname for request: %s", r->hostname
		);
		return;
	}

	entry = shGetLockedEntry(shtable, keyHash);
	if (entry == (struct shEntry *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"shGetLockedEntry(%lx, \"%s\") failed in watchPostReadRequestHash()",
			(unsigned long) shtable, keyHash
		);
		return;
	}

	/* Register a clean-up handler before we count the active
	 * connection. This could lead to a negative value during
	 * cleanup if the connection is dropped between the
	 * ap_register_cleanup() call and the counter increment.
	 *
	 * Reversing the following two lines can result in a very
	 * rare condition where a connection is counted, then drops
	 * between the two lines, and then is never uncounted. At
	 * least the other way we can detect the condition more
	 * readily.
	 *
	 * Of course the connection could be dropped before we even
	 * get this far, which doesn't matter.
	 *
	 * Note that ALL requests, including watch handlers, are
	 * counted in this phase since its too early to detect our
	 * handler. I could do a subrequest to find out, but I see
	 * little benefit in filtering out the handlers.
	 */
	apr_pool_cleanup_register(
		r->pool, (char *) keyHash,
		watchCleanUpHash, apr_pool_cleanup_null
	);
	entry->ifActive++;

	ap_log_error(
		APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, watchMainServer,
		"watchPostReadRequestHash(%lx, %s, %s) active=%d",
		r, keyNotes, keyHash, entry->ifActive
	);

	copy = apr_palloc(r->pool, sizeof *copy);
	*copy = *entry;
	apr_table_setn(r->notes, keyNotes, (char *) copy);

	if (shUnlock(shtable)) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"shUnlock(%lx) failed in watchPostReadRequestHash()",
			(unsigned long) shtable
		);
	}
}

/*
 * This handler is used in Phase 0 to store the current values of the
 * counters BEFORE this request is completed in the request_rec->notes
 * table. This allows other modules to make use of these counters.
 *
 * Other 3rd party modules can obtain the values of the counters at the
 * start of Phase 1. The values are stored in the request_rec->notes
 * table with the following key names:
 *
 *	watch-file-owner
 *	watch-virtual-host
 *	watch-server
 *	watch-remote-ip
 *	watch-location
 *
 * The value returned from apr_table_get() must be cast to a structure
 * pointer. The structure should be declared as:
 *
 *	struct watchEntry {
 *		char *key;
 *		unsigned long ifInOctets;
 *		unsigned long ifOutOctets;
 *		unsigned long ifRequests;
 *		unsigned long ifDocuments;
 *		unsigned lomg ifOutRate;
 *		short         ifActive;
 *	};
 *
 * For example:
 *
 *	struct watchEntry *entry;
 *	entry = (struct watchEntry *) apr_table_get(r->notes, "watch-virtual-host");
 *
 * These values are a per request copy of the data stored by mod_watch,
 * and should be considered read-only so that other modules can benefit
 * from them. Changing the values here will not affect the originals
 * maintained by mod_watch.
 */
static int
watchPostReadRequest(request_rec *r)
{
	char *key;
	struct watchConfDir *dconf;

	/* Do not count if the connection is excluded. */
	if (ntIsMember(networkExcludeList, r->connection->remote_addr)
	&& !ntIsMember(networkIncludeList, r->connection->remote_addr))
		return DECLINED;

	if (watch_what & (WATCH_OWNER|WATCH_OWNER_BY_PORT)) {
		key = (char *) userGetName(r->pool, r->finfo.user);

		if (watch_what & WATCH_OWNER)
			watchPostReadRequestHash(r, "watch-file-owner", key);

		if (watch_what & WATCH_OWNER_BY_PORT) {
			key = apr_psprintf(r->pool, "%s,%u", key, ap_get_server_port(r));
			watchPostReadRequestHash(r, "watch-file-owner-by-port", key);
		}
	}

	if ((key = watchGetCanonicalName(r)) != (char *) 0) {
		if (watch_what & WATCH_VHOST)
			watchPostReadRequestHash(r, "watch-virtual-host", key);

		if (watch_what & WATCH_VHOST_BY_PORT) {
			key = apr_psprintf(r->pool, "%s,%u", key, ap_get_server_port(r));
			watchPostReadRequestHash(r, "watch-virtual-host-by-port", key);
		}
	}

	if (watch_what & WATCH_SERVER)
		watchPostReadRequestHash(r, "watch-server", SERVER);

	if (watch_what & WATCH_OWNER_BY_PORT) {
		key = apr_psprintf(r->pool, "%s,%u", SERVER, ap_get_server_port(r));
		watchPostReadRequestHash(r, "watch-server-by-port", key);
	}

	if (watch_what & WATCH_REMOTE_IP) {
		key = apr_psprintf(r->pool, "ip/%s", r->connection->remote_ip);
		watchPostReadRequestHash(r, "watch-remote-ip", key);
	}

	if (watch_what & WATCH_REMOTE_IP_BY_PORT) {
		key = apr_psprintf(r->pool, "ip/%s,%u", r->connection->remote_ip, ap_get_server_port(r));
		watchPostReadRequestHash(r, "watch-remote-ip-by-port", key);
	}

	dconf = (struct watchConfDir *) ap_get_module_config(r->per_dir_config, &watch_module);

	if (dconf != (struct watchConfDir *) 0 && dconf->index != UNSET)
		watchPostReadRequestHash(r, "watch-location", ((char **) watchStateFileList->elts)[dconf->index]);

	return DECLINED;
}

static void
watchLogEntry(struct shEntry *entry, struct shEntry *data)
{
	unsigned long now;

	entry->ifInOctets  += data->ifInOctets;
	entry->ifOutOctets += data->ifOutOctets;
	entry->ifRequests  += data->ifRequests;
	entry->ifDocuments += data->ifDocuments;

	/* Compute an average on the next request after at least N
	 * seconds of real time have passed. Calculation not done
	 * at regular intervals, because frequency of requests is
	 * irregular.
	 */
	now = (unsigned long) time((time_t *) 0);
	entry->periodOctets += data->ifOutOctets;

	if (entry->periodMarker == 0) {
		entry->periodMarker = now;
	} else if (entry->periodMarker + SECONDS_PER_PERIOD <= now) {
		entry->ifOutRate = entry->periodOctets * 1.0 / (now - entry->periodMarker);
		entry->periodMarker = now;
		entry->periodOctets = 0;
	}
}

static void
watchLogHash(request_rec *r, const char *name, struct shEntry *data)
{
	unsigned long rate;
	struct shEntry *entry;

	if (name == (char *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_INFO, APR_SUCCESS, watchMainServer,
			"not logged, bogus hostname for request: %s", r->hostname
		);
		return;
	}

	entry = shGetLockedEntry(shtable, name);

	if (entry == (struct shEntry *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"shGetLockedEntry(%lx, \"%s\") failed in watchLogHash()",
			(unsigned long) shtable, name
		);
		return;
	}

	watchLogEntry(entry, data);

	if (shUnlock(shtable)) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"shUnlock(%lx) failed in watchLogHash()",
			(unsigned long) shtable
		);
	}
}

static int
watchLog(request_rec *r)
{
	char *key;
	struct shEntry *data;
	struct watchConfDir *dconf = (struct watchConfDir *) ap_get_module_config(
		r->per_dir_config, &watch_module
	);

	/* Do this BEFORE possibly ignoring a watch handler, because a side
	 * effect of watchCounters() is to reset the watchConnectionIO
	 * structure in preparation for other requests on the same connection.
	 */
	data = watchCounters(r);

	/* Do not count the watch-* reports. */
	if (!watch_log_all && r->handler != (char *) 0 && ap_strcasecmp_match(r->handler, "watch-*") == 0) {
		/* FIXME: Is this still true in Apache 2? */

		/* The Writing Apache Modules book on p78 states that all the
		 * log phase handlers are executed regardless of whether they
		 * return OK or DECLINED. A log handler can short-circuit the
		 * remaining log handlers if it returns something other than
		 * OK or DECLINED. This is highly dependant on module load
		 * order and could affect the correct opertaion of other
		 * modules if used.
		 *
		 * The cleaner way to do this is through the httpd.conf file:
		 *
		 *	# Disable the previous CustomLog directive.
		 * 	#CustomLog logs/access_log common
		 *	SetEnvIf Request_URI "/watch-info$" IGNORE
		 *	CustomLog /dev/null common env=IGNORE
		 *	CustomLog logs/access_log common env=!IGNORE
		 */
		return r->status;
	}

	/* Do not count if the connection is excluded. */
	if (ntIsMember(networkExcludeList, r->connection->remote_addr)
	&& !ntIsMember(networkIncludeList, r->connection->remote_addr))
		return DECLINED;

#ifdef WATCH_OUTPUT_VERSION_3
	/* Find last sub-request for bytes actually sent. */
	for ( ; r->next != (request_rec *) 0; r = r->next)
		;
#endif

	if (watch_what & (WATCH_OWNER|WATCH_OWNER_BY_PORT)) {
		key = (char *) userGetName(r->pool, r->finfo.user);

		if (watch_what & WATCH_OWNER)
			watchLogHash(r, key, data);

		if (watch_what & WATCH_OWNER_BY_PORT) {
			key = apr_psprintf(r->pool, "%s,%u", key, ap_get_server_port(r));
			watchLogHash(r, key, data);
		}
	}

	if ((key = watchGetCanonicalName(r)) != (char *) 0) {
		if (watch_what & WATCH_VHOST)
			watchLogHash(r, key, data);

		if (watch_what & WATCH_VHOST_BY_PORT) {
			key = apr_psprintf(r->pool, "%s,%u", key, ap_get_server_port(r));
			watchLogHash(r, key, data);
		}
	}

	if (watch_what & WATCH_SERVER)
		watchLogHash(r, SERVER, data);

	if (watch_what & WATCH_SERVER_BY_PORT) {
		key = apr_psprintf(r->pool, "%s,%u", SERVER, ap_get_server_port(r));
		watchLogHash(r, key, data);
	}

	if (watch_what & WATCH_REMOTE_IP) {
		key = apr_psprintf(r->pool, "ip/%s", r->connection->remote_ip);
		watchLogHash(r, key, data);
	}

	if (watch_what & WATCH_REMOTE_IP_BY_PORT) {
		key = apr_psprintf(r->pool, "ip/%s,%u", r->connection->remote_ip, ap_get_server_port(r));
		watchLogHash(r, key, data);
	}

	if (dconf != (struct watchConfDir *) 0 && dconf->index != UNSET)
		watchLogHash(r, ((char **) watchStateFileList->elts)[dconf->index], data);

	return DECLINED;
}

/***********************************************************************
 ***  Content handlers.
 ***********************************************************************/

static int
watchFlush(request_rec *r)
{
	if (r->handler == (char *) 0 || ap_strcmp_match(r->handler, watch_flush) != 0)
		return DECLINED;

	ap_set_content_type(r, "text/plain");

#ifdef WHAT_IS_NEW_API
	ap_send_http_header(r);
#endif

	if (!shLock(shtable))
		shFlushAll(shtable);
	shUnlock(shtable);

	ap_rprintf(r, "OK\n");

	return OK;
}

static void
watchInfoLine(request_rec *r, struct shEntry *entry, int index_ignored)
{
	ap_rprintf(
		r, "%s %lu ",
		entry->key, apr_time_sec(r->request_time - watchRestartTime)
	);

	ap_rprintf(
		r, shPrintFormat,
		entry->ifInOctets,
		entry->ifOutOctets,
		entry->ifRequests,
		entry->ifDocuments,
		entry->ifActive,
		entry->ifOutRate
	);
	ap_rprintf(r, "\n");
}

/*
 * Write the content, which is single text line containing the
 * target name, server uptime in seconds, octets in, octets out,
 * requests in, and documents out.
 */
static int
watchInfo(request_rec *r)
{
	int rc;
	const char *name;
	struct shEntry *entry, *copy;

	if (r->handler == (char *) 0 || ap_strcmp_match(r->handler, watch_info) != 0)
		return DECLINED;

	if ((name = watchTarget(r)) == (const char *) 0)
		return HTTP_NOT_FOUND;

	if (!shContainsKey(shtable, name))
		return HTTP_NOT_FOUND;

	ap_set_content_type(r, "text/plain");

#ifdef WHAT_IS_NEW_API
	ap_send_http_header(r);
#endif
	if (r->header_only)
		return OK;

	copy = apr_palloc(r->pool, sizeof *copy);

#ifdef DISCARD_REQUEST_BODY
	if ((rc = ap_discard_request_body(r)) != OK)
		return rc;
#endif

	entry = shGetLockedEntry(shtable, name);

	if (entry == (struct shEntry *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"shGetLockedEntry(%lx, \"%s\") failed in watchContentInfoHash()",
			(unsigned long) shtable, name
		);

		memset(copy, 0, sizeof *copy);
		copy->key = (char *) name;
	} else {
		*copy = *entry;

		if (shUnlock(shtable)) {
			ap_log_error(
				APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
				"shUnlock(%lx) failed in watchContentInfoHash()",
				(unsigned long) shtable
			);
		}
	}

	watchInfoLine(r, entry, -1);

	return OK;
}

static int
watchReadWeenieFile(request_rec *r, const char *name, struct shEntry *fill)
{
	int rc = -1;
	long active;
	apr_file_t *fp;
	const char *file;

	memset(fill, 0, sizeof *fill);
	if ((file = apr_pstrcat(r->pool, stateDirectory, name, (char *) 0)) == (char *) 0)
		goto error0;

	rc = apr_file_open(&fp, file, APR_READ|APR_BUFFERED, APR_OS_DEFAULT, r->pool);
	if (rc != APR_SUCCESS)
		goto error0;

	fill->key = apr_pstrdup(r->pool, name);

	/*** Grrr... There is no apr_file_scanf() for reading in the
	 *** structured data from the one line files. Do it the long
	 *** way.
	 ***/

	if (fileReadFormat(fp, &fill->ifInOctets, SH_OCTET_COUNTER_SCAN_FORMAT) != APR_SUCCESS)
		goto error1;
	if (fileReadFormat(fp, &fill->ifOutOctets, SH_OCTET_COUNTER_SCAN_FORMAT) != APR_SUCCESS)
		goto error1;
	if (fileReadFormat(fp, &fill->ifRequests, "%lu") != APR_SUCCESS)
		goto error1;
	if (fileReadFormat(fp, &fill->ifDocuments, "%lu") != APR_SUCCESS)
		goto error1;

	if (fileReadFormat(fp, &active, "%hd") != APR_SUCCESS)
		goto error1;
	fill->ifActive = (short) active;

	if (fileReadFormat(fp, &fill->ifOutRate, "%lf") != APR_SUCCESS)
		goto error1;

	if (fileReadFormat(fp, &fill->periodOctets, "%lu") != APR_SUCCESS)
		goto error1;
	if (fileReadFormat(fp, &fill->periodMarker, "%lu") != APR_SUCCESS)
		goto error1;

	rc = 0;
error1:
	(void) apr_file_close(fp);
error0:
	return rc;
}

void
watchPrintTree(request_rec *r, char *directory, watch_print_entry printfn)
{
	apr_dir_t *dir;
	apr_finfo_t finfo;
	struct shEntry entry;

	/* List all weenie files NOT loaded into the hash table. */
	if (apr_dir_open(&dir, directory, r->pool) != APR_SUCCESS)
		return;

	while (apr_dir_read(&finfo, APR_FINFO_TYPE|APR_FINFO_NAME, dir) == APR_SUCCESS) {
		if (*finfo.name == '.' || strcmp(finfo.name, shLockFile) == 0)
			continue;

		if (finfo.filetype == APR_DIR) {
			char *subdir = apr_pstrcat(r->pool, directory, "/", finfo.name, NULL);
			watchPrintTree(r, subdir, printfn);
			continue;
		}

		if (shContainsKey(shtable, finfo.name))
			continue;

		if (watchReadWeenieFile(r, finfo.name, &entry))
			continue;

		(*printfn)(r, &entry, -1);
	}

	apr_dir_close(dir);
}

static int
watchList(request_rec *r)
{
	int i, rc;
	struct shEntry *array, entry;

	if (r->handler == (char *) 0 || ap_strcmp_match(r->handler, watch_list) != 0)
		return DECLINED;

	ap_set_content_type(r, "text/plain");

#ifdef WHAT_IS_NEW_API
	ap_send_http_header(r);
#endif
	if (r->header_only)
		goto error0;

	if (shLock(shtable))
		goto error0;

	array = shtable->array;
	for (i = 0; i < shTableSize; ++i) {
		if (array[i].key != (char *) 0)
			watchInfoLine(r, &array[i], i);
	}

	watchPrintTree(r, stateDirectory, watchInfoLine);
error1:
	(void) shUnlock(shtable);
error0:
	return OK;
}

static void
watchTablePrint(request_rec *r, struct shEntry *entry, int index)
{
	unsigned long hash;

	hash = shHashCode(0, entry->key);

	ap_rprintf(r, "<tr align='right'>\n");
	ap_rprintf(
		r, "<td>%s</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%.3f</td><td>%hd</td>\n",
		entry->key,
		hash,
		hash % shTableSize,
		index,
		entry->ifInOctets,
		entry->ifOutOctets,
		entry->ifRequests,
		entry->ifDocuments,
		entry->ifOutRate,
		entry->ifActive
	);
	ap_rprintf(r, "</tr>\n");
}

static int
watchTable(request_rec *r)
{
	int i;
	unsigned long hash;
	struct dirent *dirent;
	struct shEntry *array, entry;

	if (r->handler == (char *) 0 || ap_strcmp_match(r->handler, watch_table) != 0)
		return DECLINED;

	ap_set_content_type(r, "text/html");

#ifdef WHAT_IS_NEW_API
	ap_send_http_header(r);
#endif
	if (r->header_only)
		goto error0;

	if (shLock(shtable))
		goto error0;

	ap_rprintf(r, "<html>");
	ap_rprintf(r, "<style type='text/css'>");
	ap_rprintf(r, "th {");
	ap_rprintf(r, "  font-family: Verdana, Arial, Helvetica, sans-serif;");
	ap_rprintf(r, "  font-size: 10pt;");
	ap_rprintf(r, "  background-color: #0080D7;");
	ap_rprintf(r, "  color: #ffffff;");
	ap_rprintf(r, "}");
	ap_rprintf(r, ".normal, p, ul, td {");
	ap_rprintf(r, "  font-family: Verdana, Arial, Helvetica, sans-serif;");
	ap_rprintf(r, "  font-size: 10pt;");
	ap_rprintf(r, "  color: #000000;");
	ap_rprintf(r, "}");
	ap_rprintf(r, "</style>");
	ap_rprintf(r, "<body>");

	/* Module version, copyright, and license link. */
	ap_rprintf(r, "<p align='center'>"MODULE"/"VERSION"<br>\n");
	ap_rprintf(r, "<a href='" LICENSE_URL "'>License, Disclaimer, and Support details.</a><br>\n");
	ap_rprintf(r, COPYRIGHT "\n");
	ap_rprintf(r, "</p>\n");

	/* Shared memory hash table details. */
	ap_rprintf(r, "<table width='100%%' border='0' cellpadding='0' cellspacing='0'>\n");
	ap_rprintf(r, "<tr align='center'>\n");
	ap_rprintf(r, "<th>Table Size</th><th>Found</th><th>Probes</th><th>Faults</th><th>Flushes</th><th>Shared Memory Remaining</th>\n");
	ap_rprintf(r, "</tr>\n");
	ap_rprintf(r, "<tr align='center'>\n");
	ap_rprintf(
		r, "<td>%d</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td>\n",
		shtable->size, shtable->info->found, shtable->info->probes,
		shtable->info->faults, shtable->info->flushes,
		MemoryAvailable(shtable->memory)

	);
	ap_rprintf(r, "</tr>\n");
	ap_rprintf(r, "</table>\n");

	/* Shared memory hash table headings. */
	ap_rprintf(r, "<table width='100%%' border='0' cellpadding='1' cellspacing='0'>\n");
	ap_rprintf(r, "<tr align='right'>\n");
	ap_rprintf(r, "<th>Key</th><th>Hash</th><th>Optimal</th><th>Index</th><th>InOctets</th><th>OutOctets</th><th>Requests</th><th>Documents</th><th>B/s</th><th>Active</th>\n");
	ap_rprintf(r, "</tr>\n");

	/* Shared memory hash table contents dump. */
	array = shtable->array;
	for (i = 0; i < shTableSize; ++i) {
		if (array[i].key != (char *) 0)
			watchTablePrint(r, &array[i], i);
	}

	watchPrintTree(r, stateDirectory, watchTablePrint);
error1:
	ap_rprintf(r, "</table>\n");
	ap_rprintf(r, "</body></html>\n");
	(void) shUnlock(shtable);
error0:
	return OK;
}

/***********************************************************************
 *** Server configuration, merge, and initialisation.
 ***********************************************************************/

static void *
watchCreateDir(apr_pool_t *p, char *dir)
{
	struct watchConfDir *conf = apr_pcalloc(p, sizeof *conf);

	conf->index = UNSET;

	return (void *) conf;
}

static int
watchPreConfig(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
#if defined(WHEN_APACHE_EXPLAINS_WHAT_TO_DO) && defined(__unix__)
	unixd_pre_config(ptemp);
#endif
	watchDocumentsList = apr_array_make(pconf, 0, sizeof *watchDocumentsDef);
	networkIncludeList = apr_array_make(pconf, 0, sizeof (apr_ipsubnet_t *));
	networkExcludeList = apr_array_make(pconf, 0, sizeof (apr_ipsubnet_t *));
	watchStateFileList = apr_array_make(pconf, 0, sizeof (char *));
	(void) setDirectory(pconf, STATEDIR, &stateDirectory);

	watch_what = WATCH_DEFAULT | WATCH_VHOST | WATCH_SERVER;
	watchDynamicVirtualHost = -1;
	watch_log_all = 0;

	shTableSize = TABLE_SIZE;

        return OK;
}

static int
watchPostConfig(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	char *stateDirectoryIp;

        ap_add_version_component(pconf, MODULE "/" VERSION);

	/* Handy to have for error logging. */
	watchMainServer = s;

	watchRestartTime = apr_time_now();

	/* Is mod_vhost_alias in play? */
	watchDynamicVirtualHost = (watchDynamicVirtualHost == -1) && (
		(ap_find_linked_module("mod_vhost_alias.c") != (module *) 0) ||
		(ap_find_linked_module("mod_vd.c") != (module *) 0)
	);

	/* If no WatchDocuments specified, use defaults. */
	if (watchDocumentsList->nelts <= 0) {
		const char **list, **mime;

		for (list = watchDocumentsDef; *list != (char *) 0; ++list) {
			mime = (const char **) apr_array_push(watchDocumentsList);
			if (mime == (const char **) 0)
				exit(APEXIT_INIT);
			*mime = *list;
		}
	}

	stateDirectoryIp = apr_pstrcat(ptemp, stateDirectory, "ip", NULL);
	if (apr_dir_make_recursive(stateDirectoryIp, APR_OS_DEFAULT, ptemp))
		exit(APEXIT_INIT);

#if defined(__unix__)
	/* Make sure the Apache server owns this directory so that preforked
	 * child processes can R/W to it later when ever they need to flush
	 * or dump shared memory hash table entries to disk.
	 */
	(void) chown(stateDirectory, unixd_config.user_id, unixd_config.group_id);
	(void) chown(stateDirectoryIp, unixd_config.user_id, unixd_config.group_id);
#endif

	/* Create shared memory hash table. */
	shtable = shCreate(pconf, shTableSize, stateDirectory);
	if (shtable == (struct shTable *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"shCreate(%lx, %lu, %s) failed in watchPostConfig()",
			(unsigned long) pconf, shTableSize, stateDirectory
		);
		exit(APEXIT_INIT);
	}

	apr_pool_cleanup_register(pconf, shtable, shDestroy, apr_pool_cleanup_null);

        return OK;
}

static void
watchChildInit(apr_pool_t *p, server_rec *s)
{
#if defined(WHEN_APACHE_EXPLAINS_WHAT_TO_DO) && defined(__unix__)
	unixd_setup_child();
#endif
	shChildInit(shtable, p);
}

static void
watchHooks(apr_pool_t *p)
{
	ap_hook_pre_config(watchPreConfig, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(watchPostConfig, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(watchChildInit, NULL, NULL, APR_HOOK_MIDDLE);

	ap_hook_pre_connection(watchPreConnection, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_read_request(watchPostReadRequest, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_log_transaction(watchLog, NULL, NULL, APR_HOOK_MIDDLE);

	ap_register_input_filter(watch_io, watchFilterInput, NULL, AP_FTYPE_NETWORK - 1);
	ap_register_output_filter(watch_io, watchFilterOutput, NULL, AP_FTYPE_NETWORK - 1);

	ap_hook_handler(watchInfo, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(watchList, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(watchTable, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(watchFlush, NULL, NULL, APR_HOOK_MIDDLE);
}

/***********************************************************************
 ***  Configuration Directives
 ***********************************************************************/

/*
 * WatchHashTableSize number
 *
 * The size of the shared memory hash table for the "hash" storage policy.
 */
static const char *
WatchHashTableSize(cmd_parms *cmd, void *dconf, const char *number)
{
	return setUnsignedInt(number, &shTableSize);
}

/*
 * WatchStateDirectory directory
 *
 * Absolute or server root relative directory where support and runtime
 * files are kept.
 */
static const char *
WatchStateDirectory(cmd_parms *cmd, void *dconf, const char *directory)
{
	return setDirectory(cmd->pool, directory, &stateDirectory);
}

/*
 * WatchDocuments mime-type ...
 */
static const char *
WatchDocuments(cmd_parms *cmd, void *dconf, const char *arg)
{
	char **mime;

	mime = (char **) apr_array_push(watchDocumentsList);
	if (mime == (char **) 0)
		return "Cannot add to WatchDocuments list.";

	*mime = (char *) apr_pstrdup(cmd->pool, arg);

	return (const char *) 0;
}

/*
 * WatchStateFile unique-filename
 */
static const char *
WatchStateFile(cmd_parms *cmd, void *dconf, const char *filename)
{
	int i;
	char **entry, **table;

	table = (char **) watchStateFileList->elts;
	for (i = 0; i < watchStateFileList->nelts; ++i) {
		if (strcmp(filename, table[i]) == 0)
			return "WatchStateFile argument is not unique.";
	}

	((struct watchConfDir *) dconf)->index = watchStateFileList->nelts;

	entry = (char **) apr_array_push(watchStateFileList);
	if (entry == (char **) 0)
		return "Cannot add to WatchStateFile list.";

	*entry = (char *) apr_pstrdup(cmd->pool, filename);

	return (const char *) 0;
}

/*
 * WatchWhat item ...
 */
static const char *
WatchWhat(cmd_parms *cmd, void *dconf, const char *arg)
{
	/* Erase the default settings when explicitly set. */
	if (watch_what & WATCH_DEFAULT)
		watch_what = 0;

	if (ap_strcasecmp_match(arg, "nothing") == 0)
		watch_what = 0;
	else if (ap_strcasecmp_match(arg, "virtual-host") == 0)
		watch_what |= WATCH_VHOST;
	else if (ap_strcasecmp_match(arg, "virtual-host-by-port") == 0)
		watch_what |= WATCH_VHOST_BY_PORT;
	else if (ap_strcasecmp_match(arg, "file-owner") == 0)
		watch_what |= WATCH_OWNER;
	else if (ap_strcasecmp_match(arg, "file-owner-by-port") == 0)
		watch_what |= WATCH_OWNER_BY_PORT;
	else if (ap_strcasecmp_match(arg, "server") == 0)
		watch_what |= WATCH_SERVER;
	else if (ap_strcasecmp_match(arg, "server-by-port") == 0)
		watch_what |= WATCH_SERVER_BY_PORT;
	else if (ap_strcasecmp_match(arg, "remote-ip") == 0)
		watch_what |= WATCH_REMOTE_IP;
	else if (ap_strcasecmp_match(arg, "remote-ip-by-port") == 0)
		watch_what |= WATCH_REMOTE_IP_BY_PORT;
	else if (ap_strcasecmp_match(arg, "headers-in") == 0)
		watch_what |= WATCH_HEADERS_IN;
	else if (ap_strcasecmp_match(arg, "headers-out") == 0)
		watch_what |= WATCH_HEADERS_OUT;
	else if (ap_strcasecmp_match(arg, "content-length") == 0)
		watch_what |= WATCH_CONTENT_LENGTH;
	else if (ap_strcasecmp_match(arg, watch_all) == 0)
		watch_what |= (WATCH_ALL & ~WATCH_DEFAULT);
	else
		return "Invalid item for WatchWhat";

	return (const char *) 0;
}

/*
 * WatchLogAll boolean
 *
 * context: global
 */
static const char *
WatchLogAll(cmd_parms *cmd, void *dconf, const char *bool)
{
	watch_log_all = ml_istrue(bool);

	if (watch_log_all || ml_isfalse(bool))
		return (const char *) 0;

	return "Boolean word must be either true/false, on/off, yes/no, or 1/0";
}

/*
 * WatchNetwork {include|exclude} ip/mask ...
 */
static const char *
WatchNetwork(cmd_parms *cmd, void *dconf, const char *set, const char *network)
{
	if (ap_strcasecmp_match(set, "include") == 0)
		return ntAddNetwork(cmd, networkIncludeList, network);
	else if (ap_strcasecmp_match(set, "exclude") == 0)
		return ntAddNetwork(cmd, networkExcludeList, network);

	return "Invalid category for WatchNetwork";
}

/*
 * WatchDynamicVirtualHost boolean
 *
 * context: global
 */
static const char *
WatchDynamicVirtualHost(cmd_parms *cmd, void *dconf, const char *bool)
{
	watchDynamicVirtualHost = ml_istrue(bool);

	if (watchDynamicVirtualHost || ml_isfalse(bool))
		return (const char *) 0;

	return "Boolean word must be either true/false, on/off, yes/no, or 1/0";
}

static command_rec watchCommands[] = {
	AP_INIT_ITERATE(
		"WatchDocuments", WatchDocuments, NULL, RSRC_CONF,
		"List of MIME types considered to be documents."
	),

	AP_INIT_TAKE1(
		"WatchDynamicVirtualHost", WatchDynamicVirtualHost, NULL, RSRC_CONF,
		"Set true for additional support for dynamic virtual hosts."
	),

	AP_INIT_TAKE1(
		"WatchStateFile", WatchStateFile, NULL, ACCESS_CONF,
		"A unique filename per <Directory> or <Location> that is to be watched."
	),

	AP_INIT_TAKE1(
		"WatchSpoolFile", WatchStateFile, NULL, ACCESS_CONF,
		"(Depricated) Alias for WatchStateFile."
	),

	AP_INIT_TAKE1(
		"WatchHashTableSize", WatchHashTableSize, NULL, RSRC_CONF,
		"Shared memory hash table size for \"hash\" storage policy."
	),

	AP_INIT_TAKE1(
		"WatchLogAll", WatchLogAll, NULL, RSRC_CONF,
		"Count and log the watch handlers. Generate lots of log entries when set."
	),

	AP_INIT_ITERATE2(
		"WatchNetwork", WatchNetwork, NULL, RSRC_CONF,
		"Include or exclude networks (IP/mask) from being watched."
	),

	AP_INIT_TAKE1(
		"WatchStateDirectory", WatchStateDirectory, NULL, RSRC_CONF,
		"Spool directory for any support and runtime files."
	),

	AP_INIT_TAKE1(
		"WatchSpoolDirectory", WatchStateDirectory, NULL, RSRC_CONF,
		"(Depricated) Alias for WatchStateDirectory."
	),

	AP_INIT_ITERATE(
		"WatchWhat", WatchWhat, NULL, RSRC_CONF,
		"One or more items to watch: all, virtual-host, file-owner, remote-ip, server, ..."
	),

	{ NULL }
};

/***********************************************************************
 ***  Module Definition Block
 ***********************************************************************/

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA watch_module = {
	STANDARD20_MODULE_STUFF,
	watchCreateDir,		/* create per-dir    config structures */
	NULL,			/* merge  per-dir    config structures */
	NULL,			/* create per-server config structures */
	NULL,			/* merge  per-server config structures */
	watchCommands,		/* apr_table_t of config file commands */
	watchHooks		/* register hooks */
};

