/*
 * Memory.c
 *
 * Copyright 2001, 2003 by Anthony Howe.  All rights reserved.
 *
 * A generic memory manager that can be used to allocate memory
 * from larger memory blocks allocated from the heap or shared
 * memory. This is a fairly simple technique and is patterned
 * after K&R2 page 185.
 */

#undef TEST

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "Memory.h"

struct memory {
	long size;		/* Size of chunk, includes this struct. */
};

/*
 *
 */
struct memory_header {
	struct memory *first;	/* Base of memory being partitioned. */
	long size;		/* Overall size of memory block. */
};

#define MEMORY_MINIMUM_CHUNK_SIZE	(long)(sizeof (struct memory))

/*
 * The sign bit of the memeory chunk size is used to indiciate a free
 * or allocated chunk. We mask it off here to get abs(x->size).
 */
#define MEMORY_CHUNK_SIZE(x)	((x)->size < 0 ? -(x)->size : (x)->size)

#define MEMORY_CHUNK_NEXT(x)	((struct memory *)((char *)(x) + MEMORY_CHUNK_SIZE(x)))

#define MEMORY_CHUNK_ISFREE(x)	(MEMORY_MINIMUM_CHUNK_SIZE <= (x)->size)

#define MEMORY_CHUNK_ISUSED(x)	((x)->size <= -MEMORY_MINIMUM_CHUNK_SIZE)

#define MEMORY_CHUNK_TOGGLE(x)	((x)->size = -(x)->size)

/*
 * Initialise a large block of memory from which we will allocate
 * smaller chunks. Return a pointer to an opaque memory header on
 * success, otherwise null on error.
 *
 * Previous versions of this code kept the memory header within the
 * provided memory block, which works fine, but is harder to verify
 * for consistency, especially of the given block is shared memory
 * that could be changed by several processes for good or ill.
 *
 * By using an independant header allocated from the process' heap,
 * we can improve the realiablity of verification by cross checking
 * with values kept in different memory spaces.
 */
void *
MemoryCreate(void *block, long size)
{
	struct memory_header *head;

	if (block == (void *) 0 || size < MEMORY_MINIMUM_CHUNK_SIZE)
		return (void *) 0;

	head = (struct memory_header *) malloc(sizeof *head);
	if (head == (struct memory_header *) 0)
		return (void *) 0;

	head->first = (struct memory *) block;
	head->size = head->first->size = size;

	return (void *) head;
}

/*
 * Release the memory header object.
 */
void
MemoryDestroy(void *head)
{
	free(head);
}

/*
 * Return the size of either an allocated or unallocated chunk of memory.
 * The size returned does not count the memory account structure.
 */
long
MemorySizeOf(void *chunk)
{
	if (chunk == (void *) 0)
		return 0;

	return MEMORY_CHUNK_SIZE((struct memory *) chunk - 1) - MEMORY_MINIMUM_CHUNK_SIZE;
}

/*
 * Return the total amount of free space remaining for the memory
 * block or zero (0).
 */
long
MemoryAvailable(void *header)
{
	long space;
	struct memory *last, *here;
	struct memory_header *head;

	if (header == (void *) 0)
		return 0;

	head = (struct memory_header *) header;
	last = (struct memory *) ((char *) head->first + head->size);

	for (space = 0, here = head->first; here < last; ) {
		if ((long) sizeof (struct memory) < here->size)
			space += here->size - MEMORY_MINIMUM_CHUNK_SIZE;

		here = MEMORY_CHUNK_NEXT(here);
	}

	return space;
}

/*
 * Verify the internal consistency of the allocated and freed chunks
 * within the memory block being managed. Also adjacent free blocks
 * are coalesed into one. Return the overall size of the memory block,
 * otherwise 0 on error.
 */
long
MemoryVerifySize(void *header)
{
	long size;
	struct memory_header *head;
	struct memory *here, *next, *last;

	if (header == (void *) 0)
		return 0;

	head = (struct memory_header *) header;
	last = (struct memory *) ((char *) head->first + head->size);

	for (here = head->first; ; ) {
		size = MEMORY_CHUNK_SIZE(here);
		if (size < MEMORY_MINIMUM_CHUNK_SIZE)
			return 0;

		next = MEMORY_CHUNK_NEXT(here);
		if (last <= next)
			break;

		if (MEMORY_CHUNK_ISFREE(here) && MEMORY_CHUNK_ISFREE(next))
			/* Join them into one. */
			here->size += next->size;
		else
			here = next;
	}

	/* Did we leave the loop exactly where we expect to? If so then the
	 * allocated and freed memory chunk sizes all add up correctly to
	 * the memory block size.
	 */
	return next == last ? head->size : 0;
}

/*
 * Return an allocated chunk of memory at least size bytes long from the
 * the given block of memory, otherwise null on error.
 */
void *
MemoryAllocate(void *header, long size)
{
	long excess;
	struct memory_header *head;
	struct memory *here, *best, *last;

	if (header == (void *) 0)
		return 0;

	head = (struct memory_header *) header;
	last = (struct memory *) ((char *) head->first + head->size);

	if (MemoryVerifySize(header) == 0)
		return (void *) 0;

	/* Add space for accounting. */
	size += MEMORY_MINIMUM_CHUNK_SIZE;

	/* Align memory to size of long units. */
	size = (((size - 1) / sizeof (long)) + 1) * sizeof (long);

	/* Look for smallest free chunk that best fits the request. */
	for (best = here = head->first; here < last; here = MEMORY_CHUNK_NEXT(here)) {
		if (best->size < 0 || (size <= here->size && here->size < best->size))
			best = here;
	}

	/* Empty list or is the requested size too large? */
	if (best->size < size)
		return (void *) 0;

	/* Can the best chunk be split in two? */
	excess = best->size - size;

	if (MEMORY_MINIMUM_CHUNK_SIZE < excess) {
		here = (struct memory *) ((char *) best + size);
		here->size = excess;
		best->size = size;
	}

	/* Mark the best chunk as allocated with a negative size. */
	MEMORY_CHUNK_TOGGLE(best);

	return (void *) (best + 1);
}

/*
 * Set each byte of the given memory chunk to the specified byte value.
 */
void
MemorySet(void *chunk, int byte)
{
	memset(chunk, byte, MemorySizeOf(chunk));
}

/*
 * Release an allocated chunk of memory.
 */
void
MemoryFree(void *header, void *chunk)
{
	struct memory_header *head;
	struct memory *here, *last;

	if (header == (void *) 0)
		return;

	head = (struct memory_header *) header;
	last = (struct memory *) ((char *) head->first + head->size);
	here = (struct memory *) chunk - 1;

	/* Chunk allocated from this block? */
	if (here < head->first || last <= here)
		return;

	if (MEMORY_CHUNK_ISUSED(here))
		MEMORY_CHUNK_TOGGLE(here);

	/* Coalesce adjacent free chunks. */
	(void) MemoryVerifySize(header);
}

static void *
MemoryChunkResize(void *header, void *chunk, long size, int copy)
{
	void *replace;

	if (header == (void *) 0)
		return (void *) 0;

	if (chunk == (void *) 0)
		return MemoryAllocate(header, size);

	if (size <= MemorySizeOf(chunk))
		return chunk;

	if ((replace = MemoryAllocate(header, size)) == (void *) 0)
		return (void *) 0;

	if (copy)
		memcpy(replace, chunk, MemorySizeOf(chunk));

	MemoryFree(header, chunk);

	return replace;
}

/*
 * Similar to the C library realloc(), where a request for a larger
 * memory chunk results in a new memory chunk being allocated and
 * the data copied into it. It can return the same memory chunk, a
 * new memory chunk (in which case the old one will have been freed),
 * or null on error (in which case the old one has not been freed).
 */
void *
MemoryReallocate(void *header, void *chunk, long size)
{
	return MemoryChunkResize(header, chunk, size, 1);
}

/*
 * Similar to MemoryReallocate(), but does NOT preserve the
 * contents of the previous allocated chunk of memory.
 */
void *
MemoryResize(void *header, void *chunk, long size)
{
	return MemoryChunkResize(header, chunk, size, 0);
}

#if defined(TEST)

#include <stdio.h>
#include <stdlib.h>

#define MARKER		__FILE__,__LINE__

void
notNull(void *ptr, char *file, long line)
{
	if (ptr == (void *) 0) {
		printf("Expected non-null pointer at %s:%ld\n", file, line);
		exit(1);
	}
}

void
isNull(void *ptr, char *file, long line)
{
	if (ptr != (void *) 0) {
		printf("Expected null pointer at %s:%ld\n", file, line);
		exit(1);
	}
}

void
expectedChunkSize(void *block, void *chunk, long size, char *file, long line)
{
	long chunksize = ((struct memory *) chunk)[-1].size;
	printf("Memory space available: %ld\n", MemoryAvailable(block));

	if (chunksize != size) {
		printf("Unexpected chunk size %d at %s:%ld\n", chunksize, file, line);
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	void *block, *header, *first, *a, *b, *c;

	setvbuf(stdout, (char *) 0, _IOLBF, BUFSIZ);

	block = malloc(100);
	notNull(block, MARKER);
	header = MemoryCreate(block, 100);

	/************************************************************
	 * Show available free space.
	 ************************************************************/

	printf("TEST 1: Memory space available: %ld\n", MemoryAvailable(header));

	if (MemoryVerifySize(header) != 100) {
		printf("MemoryVerifySize() failed!\n");
		exit(1);
	}

	/************************************************************
	 * Allocate & free should result in initial free space.
	 ************************************************************/

	printf("TEST 2: Allocate & free should result in initial free space.\n");

	first = MemoryAllocate(header, 20);
	notNull(first, MARKER);

	expectedChunkSize(header, first, -(long)(20 + sizeof (struct memory)), MARKER);
	MemoryFree(header, first);
	expectedChunkSize(header, first, 100, MARKER);

	/************************************************************
	 * Allocate & free in different order.
	 ************************************************************/

	printf("TEST 3: Allocate & free in different order.\n");

	first = MemoryAllocate(header, 0);
	notNull(first, MARKER);
	expectedChunkSize(header, first, -(long) sizeof (struct memory), MARKER);

	a = MemoryAllocate(header, 20);
	notNull(a, MARKER);
	expectedChunkSize(header, a, -(long)(20 +  sizeof (struct memory)), MARKER);

	b = MemoryAllocate(header, 20);
	notNull(b, MARKER);
	expectedChunkSize(header, b, -(long)(20 +  sizeof (struct memory)), MARKER);

	c = MemoryAllocate(header, 20);
	notNull(c, MARKER);
	expectedChunkSize(header, c, -(long)(20 +  sizeof (struct memory)), MARKER);

	MemoryFree(header, c);
	MemoryFree(header, a);
	MemoryFree(header, b);
	expectedChunkSize(header, a, 100 - 1 * sizeof (struct memory), MARKER);

	MemoryFree(header, first);
	expectedChunkSize(header, first, 100, MARKER);

	/************************************************************
	 * Allocate beyond free space should result in null.
	 ************************************************************/

	printf("TEST 4: Allocate beyond free space should result in null.\n");

	first = MemoryAllocate(header, 0);
	notNull(first, MARKER);
	expectedChunkSize(header, first, -(long) sizeof (struct memory), MARKER);

	a = MemoryAllocate(header, 20);
	notNull(a, MARKER);
	expectedChunkSize(header, a, -(long)(20 +  sizeof (struct memory)), MARKER);

	b = MemoryAllocate(header, 40);
	notNull(b, MARKER);
	expectedChunkSize(header, b, -(long)(40 +  sizeof (struct memory)), MARKER);

	c = MemoryAllocate(header, 60);
	isNull(c, MARKER);

	MemoryFree(header, a);
	MemoryFree(header, b);
	expectedChunkSize(header, a, 100 - 1 * sizeof (struct memory), MARKER);

	MemoryFree(header, first);
	expectedChunkSize(header, first, 100, MARKER);

	/************************************************************
	 * Verify that the overal size is the same we started with.
	 ************************************************************/

	printf("TEST 5: Verify that the overal size is the same we started with.\n");

	if (MemoryVerifySize(header) != 100) {
		printf("MemoryVerifySize() failed!\n");
		exit(1);
	}

	/************************************************************
	 * Clean-Up
	 ************************************************************/

	MemoryDestroy(header);
	free(block);

	printf("OK\n");

	return 0;
}

#endif
