#include <stdio.h>
#include <stdlib.h>

#include <ev.h>
#include "buff.h"
#include "http_parser.h"
#include "server.h"
#include "utils.h"

#include "cJSON.h"
/*
 * http://www.jsonrpc.org/specification
 *
 * code	message	meaning
 * -32700	Parse error	Invalid JSON was received by the server.
 * An error occurred on the server while parsing the JSON text.
 * -32600	Invalid Request	The JSON sent is not a valid Request object.
 * -32601	Method not found	The method does not exist / is not available.
 * -32602	Invalid params	Invalid method parameter(s).
 * -32603	Internal error	Internal JSON-RPC error.
 * -32000 to -32099	Server error	Reserved for implementation-defined server-errors.
 */

#define JRPC_PARSE_ERROR		-32700
#define JRPC_INVALID_REQUEST	-32600
#define JRPC_METHOD_NOT_FOUND	-32601
#define JRPC_INVALID_PARAMS		-32603
#define JRPC_INTERNAL_ERROR		-32693

static int jrpc_send_error(struct connection* cnn, int code, char* message) {

	int res = 0;

	cJSON *error_root  = cJSON_CreateObject();

	cJSON_AddNumberToObject(error_root, "code", code);
	cJSON_AddStringToObject(error_root, "message", message);
	//cJSON *result_root = cJSON_CreateObject();
	//cJSON_AddItemToObject(result_root, "error", error_root);
	//cJSON_AddItemToObject(result_root, "id", id);

	char* str = cJSON_Print(error_root);

	http_response_head(cnn, HTTP_STATUS_BAD_REQUEST, strlen(str), NULL);
	http_response(cnn, str, strlen(str)); 
	
	free(str);
	cJSON_Delete(error_root);
	//free(message);
	return res;
}

void login(struct connection* cnn) {
	struct http_str *ctype = http_get_header(cnn, "Content-Type");
	struct http_str *clen  = http_get_header(cnn, "Content-Length");
	
	if (ctype == NULL)
		return;
	ascii_dump("Content-Type", (char* )ctype->at, ctype->len);

	if (ctype == NULL)
		return;
	ascii_dump("Content-Length", (char* )clen->at, clen->len);

	struct http_str *body = &cnn->req.body;
	if (body == NULL)
		return;
	ascii_dump("Body", (char* )body->at, body->len);

	cJSON* root = cJSON_ParseWithLength(body->at, body->len);
	if (root == NULL) {
		log_e("Parse json fail");
		jrpc_send_error(cnn, JRPC_PARSE_ERROR, "parse error");
		return;
	}
#ifdef DEBUG	
	char* str = cJSON_Print(root);
	printf("Valid JSON Received:\n%s\n", str);
	free(str);
#endif

	/** Paremter
	 */
	cJSON_Delete(root);

	/** < 0 chunk.
	 */ 
	char xx[] = "{\n  status=0\n}\r\n";
	http_response_head(cnn, HTTP_STATUS_OK, strlen(xx), NULL);
	http_response(cnn, xx, strlen(xx)); 
}

void route_test(struct connection *con)
{
	struct http_str *url = http_get_url(con);
	struct http_str *hdr = http_get_header(con, "Host");
		
	ascii_dump("url", (char* )url->at, url->len);
	ascii_dump("Host", (char*)hdr->at, hdr->len);

	/** 
	 */ 
	http_response_head(con, HTTP_STATUS_OK, HTTP_TRANSFER_CHUNCKED, NULL);
	http_response_chunk(con, "{\n");
	http_response_chunk(con, "   status: ok");
	http_response_chunk(con, "\n}\r\n");

	http_send_chunk(con, NULL, 0);
}


static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	printf("Got signal: %d\n", w->signum);
	ev_break(loop, EVBREAK_ALL);
}

int main(int argc, char **argv)
{
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal *sig_watcher = NULL;
	struct server_t *srv = NULL;

	log_i("http version: %s\n", cs_version());

	sig_watcher = calloc(1, sizeof(ev_signal));
	if (!sig_watcher)
		return -1;
	
	ev_signal_init(sig_watcher, signal_cb, SIGINT);
	ev_signal_start(loop, sig_watcher);

	srv = server_new(loop, "0.0.0.0", 8000);
	if (!srv) {
		log_e("%s(): uh_server_new failed\n", __func__);
		goto err;
	}

#if (SSL_ENABLED)
	if (ssl_init(srv, "server-cert.pem", "server-key.pem") < 0)
		goto err;
#endif

	route_register(srv, "/test", route_test);
	//route_register(srv, "/v1/login", login);
	route_register(srv, "/login", login);
	
	log_i("Listen on 8000...\n");
	ev_run(loop, 0);
	
err:
	free(sig_watcher);
	
	server_free(srv);
	return 0;
}


