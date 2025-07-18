#include <stdio.h>
#include <stdlib.h>

#include <ev.h>
#include "buff.h"
#include "http_parser.h"
#include "server.h"
#include "utils.h"

#include "cJSON.h"

#include "libnanomq.h"
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

// restart_nanomq_service 重启nanomq服务
void restart_nanomq_service(struct connection *cnn) {
    char send_jsonstr[4096] = {0};
    int ret = nanomq_restart(NULL, send_jsonstr);
    if (ret != 0) {
        log_e("restart nanomq service failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        return;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(send_jsonstr), NULL);
	http_response(cnn, send_jsonstr, strlen(send_jsonstr)); 
}

// get_nanomq_status 获取nanomq状态
void get_nanomq_status(struct connection *cnn) {
    char send_jsonstr[4096] = {0};
    int ret = nanomq_status(NULL, send_jsonstr);
    if (ret != 0) {
        log_e("get nanomq status failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        return;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(send_jsonstr), NULL);
	http_response(cnn, send_jsonstr, strlen(send_jsonstr)); 
}

void get_nanomq_config(struct connection *cnn) {
    char send_jsonstr[4096] = {0};
    int ret = nanomq_get_cfg(NULL, send_jsonstr);
    if (ret != 0) {
        log_e("get nanomq config failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        return;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(send_jsonstr), NULL);
	http_response(cnn, send_jsonstr, strlen(send_jsonstr)); 
}

void set_nanomq_config(struct connection *cnn) {
    struct http_str *ctype = http_get_header(cnn,"Content-Type");
    struct http_str *clen = http_get_header(cnn,"Content-Length");
 
	if (ctype == NULL) {
		return;
    }
	ascii_dump("Content-Type", (char* )ctype->at, ctype->len);

    if (clen == NULL) {
        return;
    }
    ascii_dump("Content-Length", (char* )clen->at, clen->len);

	struct http_str *body = &cnn->req.body;
	if (body == NULL) {
		return;
    }
	ascii_dump("Body", (char* )body->at, body->len);

	cJSON *root = cJSON_ParseWithLength(body->at, body->len);
	if (root == NULL) {
		log_e("Parse json fail");
		jrpc_send_error(cnn, JRPC_PARSE_ERROR, "parse error");
		return;
	}

	char *in_json = cJSON_Print(root);
    char out_json[4096] = {0};
#ifdef DEBUG	
	printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = nanomq_set_cfg(in_json, out_json);
    if (ret != 0) {
        log_e("set nanomq config failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        goto EXIT;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
	http_response(cnn, out_json, strlen(out_json)); 

EXIT:
    if (in_json) 
        free(in_json);
    if (root)
        cJSON_Delete(root);
}

void get_mqtt_auth_config(struct connection *cnn) {
    printf("===========\n");
    char send_jsonstr[4096] = {0};
    int ret = mqtt_auth_get_cfg(NULL, send_jsonstr);
    if (ret != 0) {
        log_e("get mqttauth config failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        return;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(send_jsonstr), NULL);
	http_response(cnn, send_jsonstr, strlen(send_jsonstr)); 
}

void set_mqtt_auth_config(struct connection *cnn) {
    struct http_str *ctype = http_get_header(cnn,"Content-Type");
    struct http_str *clen = http_get_header(cnn,"Content-Length");
 
	if (ctype == NULL) {
		return;
    }
	ascii_dump("Content-Type", (char* )ctype->at, ctype->len);

    if (clen == NULL) {
        return;
    }
    ascii_dump("Content-Length", (char* )clen->at, clen->len);

	struct http_str *body = &cnn->req.body;
	if (body == NULL) {
		return;
    }
	ascii_dump("Body", (char* )body->at, body->len);

	cJSON *root = cJSON_ParseWithLength(body->at, body->len);
	if (root == NULL) {
		log_e("Parse json fail");
		jrpc_send_error(cnn, JRPC_PARSE_ERROR, "parse error");
		return;
	}

	char *in_json = cJSON_Print(root);
    char out_json[4096] = {0};
#ifdef DEBUG	
	printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = mqtt_auth_set_cfg(in_json, out_json);
    if (ret != 0) {
        log_e("set mqttauth config failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        goto EXIT;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
	http_response(cnn, out_json, strlen(out_json)); 

EXIT:
    if (in_json) 
        free(in_json);
    if (root)
        cJSON_Delete(root);
}
