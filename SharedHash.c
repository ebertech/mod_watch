/*
 * SharedHash.c
 *
 * Shared memory hash table with long term disk storage.
 *
 * Copyright 2001, 2003 by Anthony Howe.  All rights reserved.
 */

/*
 * Maximum number of linear probes when searching the hash table
 * before swapping the oldest entry out to disk. I recommend a
 * small number betweeb 3 and 20. I think it is better to swap
 * out to disk an entry than spend too much time searching.
 *
 * This could be a module configuration option, but I am of the
 * opinion too many choices can result in poor performance. Best
 * to keep this as a small and reasonable constant.
 */
#ifndef MAX_PROBES
#define MAX_PROBES		8
#endif

/*
 * The average length of a key string. Used in computing extra
 * space required to store key strings in shared memory. When
 * key string space is exhausted, some hash entries are flushed
 * to disk to make room for newer entries.
 */
#ifndef AVERAGE_KEY_LENGTH
#define AVERAGE_KEY_LENGTH	20
#endif

/*
 * The longest supported key string. This should account for IP
 * addresses in ASCII, user names, virtual host names like
 * www.domain.tld and subdomain.domain.tld.  From what I recall,
 * domain names can be 22 characters plus a dot plus a 4 character
 * top-level-domain. I've allowed for extra space to account for
 * machine or sub-domain names.
 */
#ifndef MAX_KEY_LENGTH
#define MAX_KEY_LENGTH		128
#endif

#define BOUNDARY_CHECKING	1

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#include "httpd.h"
#include "http_log.h"

#include "apr.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "apr_strings.h"

#define APR_WANT_STDIO
#include "apr_want.h"

#if defined(__unix__)
#include "unixd.h"
#endif

#ifdef USE_UNIX_SHM_PATCH_INSTEAD
#if defined(__unix__)
#	if defined(APR_USE_SHMEM_SHMGET) || defined(APR_USE_SHMEM_SHMGET_ANON)
#		include <sys/shm.h>

/* Copied from httpd-2.0.44/srclib/apr/include/arch/unix/apr_arch_shm.h */
struct hack_apr_shm_t {
	apr_pool_t *pool;
	void *base;		/* base real address */
	void *usable;		/* base usable address */
	apr_size_t reqsize;	/* requested segment size */
	apr_size_t realsize;	/* actual segment size */
	const char *filename;	/* NULL if anonymous */
#if APR_USE_SHMEM_SHMGET || APR_USE_SHMEM_SHMGET_ANON
	int shmid;		/* shmem ID returned from shmget() */
#endif
};

#	endif
#endif
#endif

extern server_rec *watchMainServer;

#include "Memory.h"
#include "SharedHash.h"

const char shLockFile[] = "SharedHash.lock";

const char shScanFormat[] = SH_SCAN_FORMAT;
const char shPrintFormat[] = SH_PRINT_FORMAT;

#ifdef BOUNDARY_CHECKING
char *
shVerifyString(struct shTable *tp, char *str)
{
	if ((char *) tp->shared <= str && str < (char *) tp->eshared) {
		if (str + strlen(str) < (char *) tp->eshared)
			return str;
	}

	return (char *) 0;
}
#endif

int
shLock(struct shTable *tp)
{
	if (tp == (struct shTable *) 0)
		return -1;

	/* Negative logic return code expected. */
	return apr_global_mutex_lock(tp->mutex) != APR_SUCCESS;
}

int
shUnlock(struct shTable *tp)
{
	if (tp == (struct shTable *) 0)
		return -1;

	/* Negative logic return code expected. */
	return apr_global_mutex_unlock(tp->mutex) != APR_SUCCESS;
}

/*
 * Store a shared memory hash table entry to disk.
 */
static void
shStore(struct shTable *tp, struct shEntry *entry)
{
	FILE *fp;
	char *sharedKey;

	if (entry == (struct shEntry *) 0)
		return;

#ifdef BOUNDARY_CHECKING
	if ((sharedKey = shVerifyString(tp, entry->key)) == (char *) 0)
		return;
#else
	if ((sharedKey = entry->key) == (char *) 0)
		return;
#endif

	/* ASSUME the workdir string has a trailing directory separator. */
	strcpy(tp->pathname, tp->workdir);
	strncat(tp->pathname, sharedKey, MAX_KEY_LENGTH);

	if ((fp = fopen(tp->pathname, "w")) != (FILE *) 0) {
		(void) fprintf(fp, shPrintFormat, SH_PRINT_ARGS);
		(void) fprintf(fp, "\n");
		fclose(fp);
#if defined(__unix__)
		(void) chown(tp->pathname, unixd_config.user_id, unixd_config.group_id);
#endif
	}
}

/*
 * Flush the entier shared memeory hash table to disk, releasing
 * the memory assigned for all the key strings.
 */
void
shFlushAll(struct shTable *tp)
{
	struct shEntry *here, *stop;

	stop = tp->array + tp->size;

	for (here = tp->array; here < stop; ++here) {
		shStore(tp, here);
		MemoryFree(tp->memory, here->key);
		here->key = (char *) 0;
	}
}

/*
 * Flush to disk a consective series of shared memory hash table
 * entries either side of the given index.
 */
static void
shFlush(struct shTable *tp, int index)
{
	int count = 0;
	struct shEntry *here, *stop;

	tp->info->flushes++;
	stop = tp->array + tp->size;

	/* Flush forward until next null. */
	here = tp->array + (index + 1) % tp->size;

	while (here->key != (char *) 0) {
		shStore(tp, here);
		MemoryFree(tp->memory, here->key);
		here->key = (char *) 0;
		count++;

		if (stop <= ++here)
			here = tp->array;
	}

	/* Flush backward until previous null. */
	here = tp->array + index;

	while (here->key != (char *) 0) {
		shStore(tp, here);
		MemoryFree(tp->memory, here->key);
		here->key = (char *) 0;
		count++;

		if (--here < tp->array)
			here = stop - 1;
	}

	if (count <= 0)
		shFlushAll(tp);
}

/*
 * Fetch a shared memory hash table entry from disk. If we run out of
 * shared memory space, then flush some entries to disk before fetching
 * the entry for the key.
 */
static struct shEntry *
shFetch(struct shTable *tp, const char *key, int index)
{
	FILE *fp;
	char *sharedKey;
	int rc, keylen = (int) strlen(key) + 1;
	struct shEntry *entry = &tp->array[index];

#ifdef BOUNDARY_CHECKING
	sharedKey = shVerifyString(tp, entry->key);
#else
	sharedKey = entry->key;
#endif

	sharedKey = MemoryResize(tp->memory, sharedKey, keylen);
	if (sharedKey == (char *) 0) {
		shFlush(tp, index);
		sharedKey = MemoryAllocate(tp->memory, keylen);
		if (sharedKey == (char *) 0) {
			return (struct shEntry *) 0;
		}
	}

	/* ASSUME the workdir string has a trailing directory separator. */
	strcpy(tp->pathname, tp->workdir);
	strncat(tp->pathname, key, MAX_KEY_LENGTH);
	strcpy(sharedKey, key);

	if ((fp = fopen(tp->pathname, "r")) != (FILE *) 0) {
		rc = fscanf(fp, shScanFormat, SH_SCAN_ARGS);
		fclose(fp);
	}

	entry->key = sharedKey;

	return entry;
}

unsigned long
shHashCode(unsigned long hash, const char *k)
{
	if (k != (const char *) 0) {
		for ( ; *k != '\0'; ++k)
			hash = (hash * 37) + *k;
	}

	return hash;
}

int
shContainsKey(struct shTable *tp, const char *key)
{
	int i;
	struct shEntry *array;
	unsigned long hash, start;

	if (tp == (struct shTable *) 0 || key == (const char *) 0)
		return 0;

	array = tp->array;
	start = hash = shHashCode(0, key) % tp->size;

	for (i = 0; i <= MAX_PROBES; ++i) {
		if (array[hash].key == (char *) 0)
			return 0;
		if (strcmp(key, array[hash].key) == 0)
			return 1;

		/* Linear probe through the table. */
		hash = (hash + 1) % tp->size;
	}

	return 0;
}

/*
 * Return a pointer to the shared memory hash table entry for the key.
 */
struct shEntry *
shGetLockedEntry(struct shTable *tp, const char *key)
{
	int i;
	const char *k;
	struct shEntry *entry;
	unsigned long hash, start;

	if (tp == (struct shTable *) 0 || key == (const char *) 0)
		return (struct shEntry *) 0;

	/* A simple hash function. Factors of either 31 or 37 are good
	 * values for text strings. If the table size is prime, then
	 * we can double-hash or linear probe through entire table.
	 */
	start = hash = shHashCode(0, key) % tp->size;

	if (apr_global_mutex_lock(tp->mutex) != APR_SUCCESS)
		return (struct shEntry *) 0;

	/* Perform a limited number of linear probes; no point in
	 * looking too far, better just to swap an entry out to disk.
	 */
	for (i = 0; i <= MAX_PROBES; ++i) {
		/* Free slot in the hash table? */
		if (tp->array[hash].key == (char *) 0) {
			if ((entry = shFetch(tp, key, hash)) == (struct shEntry *) 0) {
				ap_log_error(
					APLOG_MARK, APLOG_INFO, APR_SUCCESS, watchMainServer,
					"shFetch(%lx, key=\"%s\", hash=%d) failed filling empty entry",
					(unsigned long) tp, key, hash
				);
				(void) apr_global_mutex_unlock(tp->mutex);
			} else {
				tp->info->found++;
			}

			return entry;
		}

#ifdef BOUNDARY_CHECKING
		if (shVerifyString(tp, tp->array[hash].key) == (char *) 0) {
			ap_log_error(
				APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
				"shVerifyString(%lx, %lx) failed!",
				(unsigned long) tp,
				(unsigned long) tp->array[hash].key
			);
			(void) apr_global_mutex_unlock(tp->mutex);
			return (struct shEntry *) 0;
		}
#endif

		/* Found existing key? */
		if (strcmp(key, tp->array[hash].key) == 0) {
			tp->info->found++;
			return &tp->array[hash];
		}

		/* Linear probe through the table. */
		hash = (hash + 1) % tp->size;
		tp->info->probes++;
	}

	/* No matching key found within probing limit. Replace the
	 * initial hash starting point.
	 */
	shStore(tp, &tp->array[start]);
	if ((entry = shFetch(tp, key, start)) == (struct shEntry *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_INFO, APR_SUCCESS, watchMainServer,
			"shFetch(%lx, key=\"%s\", start=%d) failed replacing entry",
			(unsigned long) tp, key, start
		);
		(void) apr_global_mutex_unlock(tp->mutex);
	} else {
		tp->info->faults++;
	}

	return entry;
}

/*
 * Create a shared memory table.
 */
struct shTable *
shCreate(apr_pool_t *p, int size, const char *workdir)
{
	int rc;
	size_t bytes;
	struct shTable *tp;
	const char *lockfile;

	if (size <= MAX_PROBES) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"shCreate() hash table size too small (%d)",
			size
		);
		goto error0;
	}

	if (workdir == (const char *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"shCreate() workdir argument cannot be NULL",
			size
		);
		goto error0;
	}

	/* Allocate enough storage for the table management elements,
	 * which includes a pathname construction buffer.
	 */
	tp = apr_pcalloc(p, sizeof *tp + strlen(workdir) + 1 + MAX_KEY_LENGTH + 1);
	if (tp == (struct shTable *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"shCreate() failed to allocate shTable structure"
		);
		goto error0;
	}

	tp->lockfile = apr_pstrcat(p, workdir, shLockFile, (char *) 0);
	if (tp->lockfile == (const char *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"shCreate() failed to allocate lockfile string"
		);
		goto error0;
	}

	/* Space for global data. */
	bytes = sizeof *tp->info;

	/* We need enough room for an array of N entries, with an
	 * average key length of M bytes.
	 */
	bytes += size * (sizeof *tp->array + AVERAGE_KEY_LENGTH);

	/* Create anonymous memory segment and assume child processes
	 * inherit it. That was the case in the mod_watch/3 series. I'm
	 * assuming in a threaded module that the shared memory is akin
	 * to a malloc() from the process space.
	 *
	 * TODO: Is apr_rmm.h the same as Memory.h?
	 */
	rc = apr_shm_create((apr_shm_t **) &tp->shared, bytes, (const char *) 0, p);
	if (rc != APR_SUCCESS) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"shCreate(): apr_shm_create(%lx, %lu, NULL, %lx) failed",
			(unsigned long) &tp->shared, bytes, 0, (unsigned long) p
		);
		goto error0;
	}

#ifdef USE_UNIX_SHM_PATCH_INSTEAD
#if defined(APR_USE_SHMEM_SHMGET) || defined(APR_USE_SHMEM_SHMGET_ANON)
/* Setup the access permissions for the shared memory so that child processes
 * that change their user/group can still access the shared memory after. This
 * should have been done in the APR library, but I cannot find the equivalent
 * of unixd_set_global_mutex_perms() for shard memory.
 */
{
	struct shmid_ds shmbuf;
        struct hack_apr_shm_t *theMem = tp->shared;

        if (shmctl(theMem->shmid, IPC_STAT, &shmbuf) != 0) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"shCreate() failed to IPC_STAT shared memory block: %s (%d)",
			strerror(errno), errno
		);
                goto error1;
        }

        shmbuf.shm_perm.uid = unixd_config.user_id;
        shmbuf.shm_perm.gid = unixd_config.group_id;
        shmbuf.shm_perm.mode = 0600;

        if (shmctl(theMem->shmid, IPC_SET, &shmbuf) != 0) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"shCreate() failed to set ownership of shared memory block: %s (%d)",
			strerror(errno), errno
		);
                goto error1;
        }
}
#endif
#endif
	if ((tp->memory = MemoryCreate(apr_shm_baseaddr_get(tp->shared), bytes)) == (void *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"MemoryCreate(%lx, %lu) failed",
			(unsigned long) apr_shm_baseaddr_get(tp->shared), bytes
		);
		goto error1;
	}

	rc = apr_global_mutex_create(
		(apr_global_mutex_t **) &tp->mutex,
		tp->lockfile, APR_LOCK_DEFAULT, p
	);
	if (rc != APR_SUCCESS) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"apr_global_mutex_create(%lx, '%s', %d, %lx) failed",
			(unsigned long) &tp->mutex, tp->lockfile,
			APR_LOCK_DEFAULT, (unsigned long) p
		);
		goto error1;
	}

#if defined(__unix__)
	unixd_set_global_mutex_perms((apr_global_mutex_t *) tp->mutex);
#endif

	tp->info = (struct shInfo *) MemoryAllocate(tp->memory, sizeof *tp->info);
	if (tp->info == (struct shInfo *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"MemoryAllocate(%lx, %lu) #1 failed",
			(unsigned long) tp->memory, sizeof *tp->info
		);
		goto error3;
	}

	tp->array = (struct shEntry *) MemoryAllocate(tp->memory, size * sizeof *tp->array);
	if (tp->array == (struct shEntry *) 0) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, APR_SUCCESS, watchMainServer,
			"MemoryAllocate(%lx, %lu) #2 failed",
			(unsigned long) tp->memory, size * sizeof *tp->array
		);
		goto error3;
	}

	MemorySet(tp->info, 0);
	MemorySet(tp->array, 0);

	tp->pathname = (char *) tp + sizeof *tp;
	tp->eshared = apr_shm_baseaddr_get(tp->shared) + bytes;
	tp->workdir = workdir;
	tp->size = size;

	return tp;
error3:
	(void) apr_global_mutex_destroy(tp->mutex);
error2:
	MemoryDestroy(tp->memory);
error1:
	(void) apr_shm_destroy(tp->shared);
error0:
	return (struct shTable *) 0;
}

void
shChildInit(struct shTable *tp, apr_pool_t *p)
{
	int rc;

	rc = apr_global_mutex_child_init(
		(apr_global_mutex_t **) &tp->mutex, tp->lockfile, p
	);

	if (rc != APR_SUCCESS) {
		ap_log_error(
			APLOG_MARK, APLOG_CRIT, APR_EGENERAL, watchMainServer,
			"apr_global_mutex_child_init(%lx, %s, %lx) failed in shChildInit()",
			&tp->mutex, tp->lockfile, p
		);
	}
}

/*
 * Save the entrie shared memory array to disk.
 */
apr_status_t
shDestroy(void *data)
{
	struct shTable *tp = (struct shTable *) data;

	if (tp != (struct shTable *) 0) {
		shFlushAll(tp);
		(void) apr_global_mutex_destroy(tp->mutex);
		MemoryDestroy(tp->memory);
		(void) apr_shm_destroy(tp->shared);
	}

	return APR_SUCCESS;
}

