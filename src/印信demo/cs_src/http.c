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

#define __VERSION_STRING "1.0"

const char* cs_version(void) {

	return __VERSION_STRING;
}

static int on_message_begin(http_parser *parser)
{
	struct connection *c = container_of(parser, struct connection, parser);

	memset(&c->req, 0, sizeof(struct http_request));
	
	return 0;
}

static int on_url(http_parser *parser, const char *at, size_t len)
{
	struct connection *c = container_of(parser, struct connection, parser);
	
	c->req.url.at = at;
	c->req.url.len = len;
	
    return CCM_OK;
}

static int on_header_field(http_parser *parser, const char *at, size_t len)
{
	struct connection *c = container_of(parser, struct connection, parser);
	struct http_header *header = c->req.header;

	header[c->req.header_num].field.at = at;
	header[c->req.header_num].field.len = len;
	
    return CCM_OK;
}

static int on_header_value(http_parser *parser, const char *at, size_t len)
{
	struct connection *c = container_of(parser, struct connection, parser);
	struct http_header *header = c->req.header;
	
	header[c->req.header_num].value.at = at;
	header[c->req.header_num].value.len = len;
	c->req.header_num += 1;

	return CCM_OK;
}

static int on_body(http_parser *parser, const char *at, size_t len)
{
	struct connection *c = container_of(parser, struct connection, parser);
	
	if (c->req.body.at == NULL) {
		c->req.body.at = at;
	}
	
	c->req.body.len += len;
    return CCM_OK;
}


/* Return 1 for equal */
static int __value_cmp(struct http_str *h, const char *str)
{
	if (h->len != strlen(str))
		return 0;

	return (!strncasecmp(h->at, str, h->len));
}

static int on_message_complete(http_parser *parser)
{
	struct connection *c = container_of(parser, struct connection, parser);
	struct route_t *r;

#if 0	
	int i;
	struct http_header *header = c->req.header;

	log_d("Url:[%.*s]\n", (int)c->req.url.len, c->req.url.at);
	for (i = 0; i < c->req.header_num; i++) {
		log_d("[%.*s:%.*s]\n", (int)header[i].field.len, header[i].field.at,
			(int)header[i].value.len, header[i].value.at);	
	}
	log_d("Body:[%.*s]\n", (int)c->req.body.len, c->req.body.at);
#endif

	/** FIXME: Should validate URL. 
	 */
	list_for_each_entry(r, &c->srv->routes, list) {
		if (__value_cmp(&c->req.url, r->path)) {
			r->cb(c);
			return 0;
		}
	}

	http_response_error(c, HTTP_STATUS_NOT_FOUND, NULL);
	
	return 0;
}

http_parser_settings parser_settings = {
	.on_message_begin	 = on_message_begin,
	.on_url              = on_url,
	.on_header_field     = on_header_field,
	.on_header_value     = on_header_value,
	.on_body             = on_body,
	.on_message_complete = on_message_complete
};

int http_response(struct connection *con, const char *fmt, ...)
{
	int len = 0;
	va_list ap;
	char *str = NULL;

	assert(fmt);

	if (*fmt) {
		va_start(ap, fmt);
		len = vasprintf(&str, fmt, ap);
		va_end(ap);
	}
	
	if (len >= 0) {
		len = buff_send(con, str, len);
		free(str);
	}
	return len;
}

static void __send_status_line(struct connection *con, int code) {

	const char *reason = http_status_str(code);

	http_response(con, "HTTP/1.1 %d %s\r\nServer: restful %s\r\n",
								code, reason, __VERSION_STRING);
}

void http_response_head(struct connection *con, int status, int length, 
											const char *extra_headers) {
	__send_status_line(con, status);
	
	if (length < 0)
		http_response(con, "%s", "Transfer-Encoding: chunked\r\n");
	else
		http_response(con, "Content-Length: %d\r\n", length);

	if (extra_headers) 
		buff_send(con, extra_headers, strlen(extra_headers));

	buff_send(con, "\r\n", 2);
}

void http_response_error(struct connection *con, int code, const char *reason) {

	http_parser *parser = &con->parser;
	
	if (!reason)
		reason = http_status_str(code);

	if (http_should_keep_alive(parser) && code < HTTP_STATUS_BAD_REQUEST) {
		http_response_head(con, code, strlen(reason), 
				"Content-Type: text/plain\r\nConnection: keep-alive\r\n");
	} else {
		http_response_head(con, code, strlen(reason), 
				"Content-Type: text/plain\r\nConnection: close\r\n");
	}
	
	if (parser->method != HTTP_HEAD)
		buff_send(con, reason, strlen(reason));

	con->flags |= CNN_CLOSE;
}

void http_redirect(struct connection *con, int code, const char *location)
{
	char body[128] = "";

	http_parser *parser = &con->parser;
	
	snprintf(body, sizeof(body), "<p>Moved <a href=\"%s\">here</a></p>", location);  

	__send_status_line(con, code);

	http_response(con, "Location: %s\r\n"
				   "Content-Type: text/html\r\n"
				   "Content-Length: %zu\r\n"
				   "Cache-Control: no-cache\r\n", location, strlen(body));
	
	buff_send(con, "\r\n", 2);

	if (parser->method != HTTP_HEAD)
		buff_send(con, body, strlen(body));
}

int http_send_chunk(struct connection *con, const char *buf, int len)
{
	int slen = 0;
	slen += http_response(con, "%X\r\n", len);
	slen += buff_send(con, buf, len);
	slen += buff_send(con, "\r\n", 2);
	return slen;
}

int http_response_chunk(struct connection *con, const char *fmt, ...)
{
	int len = 0;
	va_list ap;
	char *str = NULL;

	assert(fmt);

	if (*fmt) {
		va_start(ap, fmt);
		len = vasprintf(&str, fmt, ap);
		va_end(ap);
	}

	if (len >= 0) {
		len = http_send_chunk(con, str, len);
		free(str);
	}

	return len;
}


inline struct http_str *http_get_url(struct connection *con)
{
	return &con->req.url;
}

struct http_str *http_get_header(struct connection *con, const char *name)
{
	int i;
	struct http_header *header = con->req.header;
	
	for (i = 0; i < con->req.header_num; i++) {
		if (__value_cmp(&header[i].field, name))
			return &header[i].value;
	}
	return NULL;
}

