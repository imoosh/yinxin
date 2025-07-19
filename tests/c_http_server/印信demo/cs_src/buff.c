#include <assert.h>
#include <string.h>

#include "buff.h"
#include "utils.h"

int buff_init(struct buff_t *buf, size_t initial_size)
{
	buf->len = buf->size = 0;

	if (buf->base) {
		free(buf->base);
		buf->base = NULL;
	}

	if (initial_size > 0) {
		buf->base = malloc(initial_size);
		if (!buf->base)
			return -1;
		buf->size = initial_size;
	}

	return 0;
}

int buff_grow(struct buff_t *buf, size_t size)
{
	void *base = realloc(buf->base, buf->size + size);
	if (!base)
		return -1;
	
	buf->base = base;
	buf->size += size;

	log_d("buff_grow:%p +%ld", buf, size);
	
	return 0;
}

void buff_free(struct buff_t *buf)
{
	buff_init(buf, 0);
}

size_t buff_append(struct buff_t *buf, const void *data, size_t len)
{
	assert(buf);

	if (!data)
		return 0;

	if (buf->len + len > buf->size) {
		if (buff_grow(buf, len * UH_BUF_SIZE_MULTIPLIER) == -1)
			len = buf->size - buf->len;
	}

	memcpy(buf->base + buf->len, data, len);
	buf->len += len;

	return len;
}

void buff_remove(struct buff_t *buf, size_t n)
{
	if (n > 0 && n <= buf->len) {
		memmove(buf->base, buf->base + n, buf->len - n);
		buf->len -= n;
	}
}
