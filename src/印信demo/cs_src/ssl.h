#ifndef _SSL_H
#define _SSL_H

#if (USE_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef SSL_SUCCESS
#define SSL_SUCCESS	1
#endif

#endif

struct connection;
struct server_t;

void ssl_ctx_free(struct server_t *srv);

void ssl_free(struct connection *con);
int  ssl_read(struct connection *con, void *buf, int count);
int  ssl_write(struct connection *con, void *buf, int count);
int  ssl_accept(struct connection *con);
void ssl_handshake(struct connection *con);

#endif
