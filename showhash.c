#include <stdio.h>
#include <stdlib.h>

unsigned long
shHashCode(unsigned long hash, const char *k)
{
	for ( ; *k != '\0'; ++k)
		hash = (hash * 37) + *k;

	return hash;
}

int
main(int argc, char **argv)
{
	long size;
	unsigned long hash;

	if (argc != 3) {
		printf("usage: showhash <table-size> <string>\n");
		return 2;
	}

	hash = shHashCode(0, argv[2]);
	size = strtol(argv[1], (char **) 0, 10);

	printf("%lu\t%lu\t%s\n", hash, hash % size, argv[2]);

	return 0;
}
