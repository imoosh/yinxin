#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

#include <stdarg.h>

#include <ev.h>
#include "http_parser.h"
#include "buff.h"

#include "server.h"
#include "list.h"
#include "ssl.h"
#include "utils.h"

static void __conn_destroy(struct connection *con)
{
	if (con) {
		struct ev_loop *loop = con->srv->loop;
	
		if (con->sock > 0)
			close(con->sock);
		
		buff_free(&con->read_buf);
		buff_free(&con->write_buf);
		
		ev_io_stop(loop, &con->read_watcher);
		ev_io_stop(loop, &con->write_watcher);
		ev_timer_stop(loop, &con->timer_watcher);

		list_del(&con->list);

		ssl_free(con);
		free(con);
	}
}

static void __timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {

	struct connection *con = container_of(w, struct connection, timer_watcher);
	log_i("connection(%p) timeout", con);

	http_response_error(con, HTTP_STATUS_REQUEST_TIMEOUT, NULL);
	__conn_destroy(con);
}

extern http_parser_settings parser_settings;

static void __read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct connection *con = container_of(w, struct connection, read_watcher);
	struct buff_t *buf = &con->read_buf;
	char *base;
	int len, parsered;
	
#if (SSL_ENABLED)
	if (con->flags & CNN_SSL_HANDSHAKE_DONE)
		goto handshake_done;

	ssl_handshake(con);
	if (con->flags & CNN_CLOSE)
		__conn_destroy(con);
	return;
	
handshake_done:
#endif

	if (buff_available(buf) < BUFFER_SIZE)
		buff_grow(buf, BUFFER_SIZE);

	base = buf->base + buf->len;
	
	len = ssl_read(con, base, BUFFER_SIZE);
	if (unlikely(len <= 0)) {
		if (con->flags & CNN_CLOSE)
			__conn_destroy(con);
		return;
	}

	buf->len += len;

	log_d("read:[%.*s]\n", len, base);

	if (!(con->flags & CNN_PARSERING)) {
		if (!memmem(buf->base, buf->len, "\r\n\r\n", 4)) {
			if (buf->len > HTTP_HEAD_MAXSIZE) {
				log_e("HTTP head size too big");
				http_response_error(con, HTTP_STATUS_BAD_REQUEST, NULL);
			}
			return;
		}
		
		base = buf->base;
		len = buf->len;
		con->flags |= CNN_PARSERING;
	}

	parsered = http_parser_execute(&con->parser, &parser_settings, base, len);
	if (unlikely(parsered != len)){
		log_e("http parser failed:%s", 
						http_errno_description(HTTP_PARSER_ERRNO(&con->parser)));
		http_response_error(con, HTTP_STATUS_BAD_REQUEST, NULL);
	} else {
		ev_timer_mode(loop, &con->timer_watcher, CONNECTION_TIMEOUT, 0);
	}
}

static void __write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct connection *con = container_of(w, struct connection, write_watcher);
	struct buff_t *buf = &con->write_buf;
	
	if (buf->len > 0) {
		int len = ssl_write(con, buf->base, buf->len);
		if (len > 0)
			buff_remove(buf, len);
	}

	if (buf->len == 0) {
		ev_io_stop(loop, w);

		if (!http_should_keep_alive(&con->parser))
			con->flags |= CNN_CLOSE;
	}

	if (con->flags & CNN_CLOSE)
		__conn_destroy(con);
}

static void __accept_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	int sock = -1;
	struct server_t *srv = container_of(w, struct server_t, read_watcher);

	struct connection *con = NULL;
	
	ev_io *read_watcher, *write_watcher;
	ev_timer *timer_watcher;
	
	con = calloc(1, sizeof(struct connection));
	if (unlikely(!con)) {
		log_e("calloc");
		return;
	}

	con->srv = srv;
	list_add(&con->list, &srv->connections);
		
	sock = ssl_accept(con);
	if (unlikely(sock < 0))
		goto err;

	read_watcher = &con->read_watcher;
	ev_io_init(read_watcher, __read_cb, sock, EV_READ);
	ev_io_start(loop,read_watcher);

	write_watcher = &con->write_watcher;
	ev_io_init(write_watcher, __write_cb, sock, EV_WRITE);

	timer_watcher = &con->timer_watcher; 
	ev_timer_init(timer_watcher, __timeout_cb, CONNECTION_TIMEOUT, 0);
	ev_timer_start(loop, timer_watcher);
		
	http_parser_init(&con->parser, HTTP_REQUEST);
	
	log_i("new connection:%p", con);
	return;
err:
	__conn_destroy(con);
}

void server_free(struct server_t *srv) {

	if (srv == NULL)
		return;

	struct connection *con, *tmp_c;
	struct route_t *r, *tmp_r;
	
	if (srv->sock > 0)
		close(srv->sock);
		
	ev_io_stop(srv->loop, &srv->read_watcher);
		
	list_for_each_entry_safe(con, tmp_c, &srv->connections, list) {
		__conn_destroy(con);
	}

	list_for_each_entry_safe(r, tmp_r, &srv->routes, list) {
		list_del(&r->list);
		free(r->path);
		free(r);
	}

	ssl_ctx_free(srv);
	free(srv);
}

struct server_t *server_new(struct ev_loop *loop, const char *ipaddr, int port)
{
	struct server_t *srv = NULL;
	struct sockaddr_in addr;
	int sock = -1, on = 1;
	ev_io *read_watcher;
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	
	if (inet_pton(AF_INET, ipaddr, &addr.sin_addr) <= 0) {
		log_e("invalid ipaddr");
		return NULL;
	}
	
	srv = calloc(1, sizeof(struct server_t));
	if (!srv) {
		log_e("calloc");
		return NULL;
	}

	INIT_LIST_HEAD(&srv->routes);
	INIT_LIST_HEAD(&srv->connections);
	
	sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		log_e("socket");
		server_free(srv);
		return NULL;
	}

	srv->sock = sock;
	srv->loop = loop;
	
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
		log_e("bind:%s", strerror(errno));
		server_free(srv);
		return NULL;

	}

	if (listen(sock, SOMAXCONN) < 0) {
		log_e("listen:%s", strerror(errno));
		server_free(srv);
		return NULL;
	}

	read_watcher = &srv->read_watcher;
	ev_io_init(read_watcher, __accept_cb, sock, EV_READ);
	ev_io_start(loop, read_watcher);
	
	return srv;
}


int buff_send(struct connection *con, const void *buf, int len) {

	len = buff_append(&con->write_buf, buf, len);
	if (len > 0)
	    ev_io_start(con->srv->loop, &con->write_watcher);

	return len;
}

int route_register(struct server_t *srv, const char *path, route_cb_t cb)
{
	struct route_t *r;

	assert(path);

	r = calloc(1, sizeof(struct route_t));
	if (!r) {
		log_e("calloc");
		return -1;
	}

	r->path = strdup(path);
	if (!r->path) {
		log_e("strdup");
		free(r);
		return -1;
	}
	
	r->cb = cb;
	list_add(&r->list, &srv->routes);
	
	return 0;	
}
