#ifndef _UHTTP_BUF_H
#define _UHTTP_BUF_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define UH_BUF_SIZE_MULTIPLIER 1.5

struct buff_t {
	char *base;		/* Buffer pointer */
	size_t len;		/* Data length */
	size_t size;	/* Buffer size */
};

#define buff_available(b) ((b)->size - (b)->len)

/* Return 0 for successful or -1 if out of memory */
int buff_init(struct buff_t *buf, size_t initial_size);
int buff_grow(struct buff_t *buf, size_t size);

void buff_free(struct buff_t *buf);

/* Append data to the buf. Return the number of bytes appended. */
size_t buff_append(struct buff_t *buf, const void *data, size_t len);

/* Remove n bytes of data from the beginning of the buffer. */
void buff_remove(struct buff_t *buf, size_t n);

#endif
