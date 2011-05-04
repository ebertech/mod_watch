/*
 * SharedHash.h
 *
 * Shared memory hash table with long term disk storage.
 *
 * Copyright 2001, 2003 by Anthony Howe.  All rights reserved.
 */

#ifndef __com_snert_mod_watch_SharedHash_h__
#define __com_snert_mod_watch_SharedHash_h__	1

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#include "apr.h"
#include <sys/types.h>

#ifdef USE_OCTET_COUNTER_64

typedef unsigned long long OctetCounter;

#define SH_SCAN_FORMAT		"%llu %llu %lu %lu %hd %lf %lu %lu"
#define SH_PRINT_FORMAT		"%lu %lu %lu %lu %hd %.3lf %lu %lu"

#define SH_OCTET_COUNTER_SCAN_FORMAT	"%llu"

#else

typedef unsigned long OctetCounter;

#define SH_SCAN_FORMAT		"%lu %lu %lu %lu %hd %lf %lu %lu"
#define SH_PRINT_FORMAT		"%lu %lu %lu %lu %hd %.3lf %lu %lu"

#define SH_OCTET_COUNTER_SCAN_FORMAT	"%lu"

#endif

/*
 * This is the data that will be kept in shared memory.
 */
struct shEntry {
	char *key;
	OctetCounter  ifInOctets;
	OctetCounter  ifOutOctets;
	unsigned long ifRequests;
	unsigned long ifDocuments;
	short         ifActive;
	double	      ifOutRate;
	unsigned long periodOctets;
	unsigned long periodMarker;
};

/* Used in shFetch() to load a shEntry from a file.
 * The key is the file name.
 */
#define SH_SCAN_ARGS 		&entry->ifInOctets,	\
				&entry->ifOutOctets,	\
				&entry->ifRequests,	\
				&entry->ifDocuments,	\
				&entry->ifActive,	\
				&entry->ifOutRate,	\
				&entry->periodOctets,	\
				&entry->periodMarker


/* Used in shStore() to save a shEntry to a file.
 * The key is the file name and need not be saved.
 */
#define SH_PRINT_ARGS		entry->ifInOctets,	\
				entry->ifOutOctets,	\
				entry->ifRequests,	\
				entry->ifDocuments,	\
				entry->ifActive,	\
				entry->ifOutRate,	\
				entry->periodOctets,	\
				entry->periodMarker

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/*
 * This statistical information will be kept in shared memory.
 */
struct shInfo {
	unsigned long found;		/* found in hash table */
	unsigned long probes;		/* number of extra probes made */
	unsigned long faults;		/* swapped to disk */
	unsigned long flushes;		/* out of shared memory */
};

/*
 * This will be kept in conventional memory.
 */
struct shTable {
	void *mutex;
	void *memory;			/* Memory header. */
	void *shared;			/* Start of shared memory block. */
	void *eshared;			/* First byte beyond the end of block.*/
	char *pathname;			/* Workdir + NAME_MAX space */
	const char *workdir;		/* The working directory. */
	const char *lockfile;		/* The mutex file name we used. */
	struct shInfo *info;		/* Statistic information. */
	struct shEntry *array;
	int size;			/* Allocated number of entries. */
};

#ifdef __cplusplus
extern "C" {
#endif

extern const char shLockFile[];
extern const char shScanFormat[];
extern const char shPrintFormat[];

extern int shLock(struct shTable *table);
extern int shUnlock(struct shTable *table);
extern void shFlushAll(struct shTable *table);
extern unsigned long shHashCode(unsigned long hash, const char *k);
extern int shContainsKey(struct shTable *table, const char *key);
extern struct shEntry *shGetLockedEntry(struct shTable *table, const char *key);
extern struct shTable *shCreate(apr_pool_t *p, int size, const char *workdir);
extern void shChildInit(struct shTable *table, apr_pool_t *p);
extern apr_status_t shDestroy(void *data);

#ifdef  __cplusplus
}
#endif

#endif /* __com_snert_mod_watch_SharedHash_h__ */
