#ifndef _SERVER_H
#define _SERVER_H

#include <ev.h>
#include "list.h"

#define BUFFER_SIZE			2048
#define CONNECTION_TIMEOUT	30
#define HTTP_HEAD_MAXSIZE	1024
#define HTTP_BODY_MAXSIZE	(2 * 1024 * 1024)
#define HTTP_HEADERS_MAX	20
#define HTTP_TRANSFER_CHUNCKED	-1

#define CNN_CLOSE				0x01
#define CNN_SSL_HANDSHAKE_DONE	0x02 /* SSL hanshake has completed */
#define CNN_PARSERING			0x04 /* Whether executed http_parser_execute()*/

#define likely(x)	(__builtin_expect(!!(x), 1))
#define unlikely(x)	(__builtin_expect(!!(x), 0))

#define ev_timer_mode(l,w,after,repeat) do { \
	ev_timer_stop(l, w); \
	ev_timer_init(w, ev_cb(w), after, repeat); \
	ev_timer_start(l, w); \
} while (0)


struct http_str {
	const char *at;
	size_t len;
};

struct connection;
typedef void (*route_cb_t)(struct connection *con);

struct route_t {
	char *path;
	route_cb_t cb;
	struct list_head list;
};

struct server_t {
	int sock;
#if (SSL_ENABLED)	
	void *ssl_ctx;
#endif
	ev_io read_watcher;
	struct ev_loop *loop;
	struct list_head routes;
	struct list_head connections;
};

struct http_header {
	struct http_str field;
	struct http_str value;
};

struct http_request {
	struct http_str url;
	struct http_str body;
	int header_num;
	struct http_header header[HTTP_HEADERS_MAX];
};

struct buff_t;

struct connection {	
	int sock;
#if (SSL_ENABLED)	
	void *ssl;
#endif
	unsigned char flags;
	struct buff_t read_buf;
	struct buff_t write_buf;

	ev_io read_watcher;
	ev_io write_watcher;
	ev_timer timer_watcher;
	struct http_request req;
	
	http_parser parser;

	struct list_head list;
	struct server_t *srv;
};

const char *cs_version(void);

struct server_t *server_new(struct ev_loop *loop, const char *ipaddr, int port);
void 			 server_free(struct server_t *srv);
/** 
 * sets a callback to be executed on a specific path
 */
int route_register(struct server_t *srv, const char *path, route_cb_t cb);

/* Sends data to the connection. */
int buff_send(struct connection *con, const void *buf, int len);

/* Sends printf-formatted data to the connection. */
int http_response(struct connection *con, const char *fmt, ...);

/*
 * Sends the response line and headers.
 * This function sends the response line with the `status`, and
 * automatically sends one header: either "Content-Length" or "Transfer-Encoding".
 * If `length` is negative, then "Transfer-Encoding: chunked" is sent, otherwise,
 * "Content-Length" is sent.
 *
 * NOTE: If `Transfer-Encoding` is `chunked`, then message body must be sent
 * using `http_send_chunk()` or `http_response()` functions.
 * Otherwise, `buff_send()` or `http_response()` must be used.
 * Extra headers could be set through `extra_headers`.
 *
 * NOTE: `extra_headers` must NOT be terminated by a new line.
 */
void http_response_head(struct connection *con, int status, int length, 
						const char *extra_headers);

/*
 * Sends a http error response. If reason is NULL, the message will be inferred
 * from the error code (if supported).
 */
void http_response_error(struct connection *con, int code, const char *reason);

/*
 * Sends a http redirect response. `code` should be either 301 
 * or 302 and `location` point to the new location.
 */
void http_redirect(struct connection *con, int code, const char *location);

/*
 * Sends data to the connection using chunked HTTP encoding.
 *
 * NOTE: The HTTP header "Transfer-Encoding: chunked" should be sent prior to 
 * using this function.
 *
 * NOTE: do not forget to send an empty chunk at the end of the response,
 * to tell the client that everything was sent.
 *
 * Example:
 *		char data[] = "Hello World";
 *		http_send_chunk(con, data, strlen(data));
 *		http_send_chunk(con, NULL, 0); // Tell the client we're finished
 */
int http_send_chunk(struct connection *con, const char *buf, int len);

/*
 * Sends a printf-formatted HTTP chunk.
 * Functionality is similar to `http_send_chunk()`.
 */
int http_response_chunk(struct connection *con, const char *fmt, ...);

struct http_str *http_get_url(struct connection *con);
struct http_str *http_get_header(struct connection *con, const char *name);

#endif
