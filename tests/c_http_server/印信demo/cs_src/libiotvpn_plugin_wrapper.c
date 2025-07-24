#include <stdio.h>
#include <stdlib.h>

#include <ev.h>
#include "buff.h"
#include "http_parser.h"
#include "server.h"
#include "utils.h"

#include "cJSON.h"

#include "libiotvpn_plugin.h"
#include "libiotvpn_plugin_wrapper.h"
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

#define FREE_ONCE(ptr) \
    if (ptr) { \
        free(ptr); \
        ptr = NULL; \
    }


//通用 证书上传 查看
void plugin_get_cert_and_other_wrapper(struct connection *cnn)
{
    char *out_json = NULL;
    int ret = plugin_get_cert_and_other(NULL, &out_json);
    if (ret != 0) {
        log_e("get cert and other failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        return;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);
}


void plugin_set_cert_and_other_wrapper(struct connection *cnn)
{
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
    char *out_json = NULL;
#ifdef DEBUG    
    printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = plugin_set_cert_and_other(in_json, &out_json);
    if (ret != 0) {
        log_e("set cert and other failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        goto EXIT;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);

EXIT:
    FREE_ONCE(in_json);
    if (root)
        cJSON_Delete(root);
}

// restart_sslvpn_service 重启sslvpn服务
void restart_sslvpn_service_wrapper(struct connection *cnn) {
    char *out_json = NULL;
    int ret = sslvpn_restart_service(NULL, &out_json);
    if (ret != 0) {
        log_e("restart sslvpn service failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        return;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);
}

// get_sslvpn_status 获取sslvpn状态
void get_sslvpn_status_wrapper(struct connection *cnn) {
    char *out_json = NULL;
    int ret = sslvpn_check_status(NULL, &out_json);
    if (ret != 0) {
        log_e("get sslvpn status failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        return;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);
}

// get_sslvpn_config 获取sslvpn配置
void get_sslvpn_config_wrapper(struct connection *cnn) {
    char *out_json = NULL;
    int ret = sslvpn_get_cfg(NULL, &out_json);
    if (ret != 0) {
        log_e("get sslvpn config failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        return;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);
}

// set_sslvpn_config 设置sslvpn配置
void set_sslvpn_config_wrapper(struct connection *cnn) {
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
    char *out_json = NULL;
#ifdef DEBUG    
    printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = sslvpn_set_cfg(in_json, &out_json);
    if (ret != 0) {
        log_e("set sslvpn config failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        goto EXIT;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);

EXIT:
    FREE_ONCE(in_json);
    if (root)
        cJSON_Delete(root);
}

// sslvpn_set_user 设置用户
void sslvpn_set_user_wrapper(struct connection *cnn) {
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
    char *out_json = NULL;
#ifdef DEBUG    
    printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = sslvpn_set_user(in_json, &out_json);
    if (ret != 0) {
        log_e("set sslvpn user failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        goto EXIT;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);

EXIT:
    FREE_ONCE(in_json);
    if (root)
        cJSON_Delete(root);
}

// sslvpn_get_user 获取用户
void sslvpn_get_user_wrapper(struct connection *cnn) {
    char *out_json = NULL;
    int ret = sslvpn_get_user(NULL, &out_json);
    if (ret != 0) {
        log_e("get sslvpn user failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        return;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);
}

// sslvpn_set_resource 设置资源
void sslvpn_set_resource_wrapper(struct connection *cnn) {
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
    char *out_json = NULL;
#ifdef DEBUG    
    printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = sslvpn_set_resource(in_json, &out_json);
    if (ret != 0) {
        log_e("set sslvpn resource failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        goto EXIT;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);

EXIT:
    FREE_ONCE(in_json);
    if (root)
        cJSON_Delete(root);
}

// sslvpn_get_resource 获取资源
void sslvpn_get_resource_wrapper(struct connection *cnn) {
    char *out_json = NULL;
    int ret = sslvpn_get_resource(NULL, &out_json);
    if (ret != 0) {
        log_e("get sslvpn resource failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        return;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);
}

// sslvpn_set_authority 设置权限
void sslvpn_set_authority_wrapper(struct connection *cnn) {
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
    char *out_json = NULL;
#ifdef DEBUG    
    printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = sslvpn_set_authority(in_json, &out_json);
    if (ret != 0) {
        log_e("set sslvpn authority failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        goto EXIT;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);

EXIT:
    FREE_ONCE(in_json);
    if (root)
        cJSON_Delete(root);
}

// sslvpn_get_authority 获取权限
void sslvpn_get_authority_wrapper(struct connection *cnn) {
    char *out_json = NULL;
    int ret = sslvpn_get_authority(NULL, &out_json);
    if (ret != 0) {
        log_e("get sslvpn authority failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        return;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);
}


////////////////////// nanomq //////////////////////

// restart_nanomq_service 重启nanomq服务
void nanomq_restart_service(struct connection *cnn) {
    char *out_json = NULL;
    int ret = nanomq_restart(NULL, &out_json);
    if (ret != 0) {
        log_e("restart nanomq service failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        goto EXIT;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
	http_response(cnn, out_json, strlen(out_json)); 

EXIT:
    if (out_json)
        free(out_json);
}

// get_nanomq_status 获取nanomq状态
void nanomq_check_status(struct connection *cnn) {
    char *out_json = NULL;
    int ret = nanomq_status(NULL, &out_json);
    if (ret != 0) {
        log_e("get nanomq status failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        goto EXIT;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
	http_response(cnn, out_json, strlen(out_json)); 
    
EXIT:
    if (out_json)
        free(out_json);
}

void nanomq_get_service_config(struct connection *cnn) {
    char *out_json = NULL;
    int ret = nanomq_get_cfg(NULL, &out_json);
    if (ret != 0) {
        log_e("get nanomq config failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        goto EXIT;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
	http_response(cnn, out_json, strlen(out_json)); 

EXIT:
    if (out_json) 
        free(out_json);
}

void nanomq_set_service_config(struct connection *cnn) {
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
    char *out_json = NULL;
#ifdef DEBUG	
	printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = nanomq_set_cfg(in_json, &out_json);
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
    if (out_json) 
        free(out_json);
    if (root)
        cJSON_Delete(root);
}

void nanomq_get_auth_config(struct connection *cnn) {
    char *out_json = NULL;
    int ret = mqtt_auth_get_cfg(NULL, &out_json);
    if (ret != 0) {
        log_e("get mqttauth config failed");
		jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        goto EXIT;
    }

	http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
	http_response(cnn, out_json, strlen(out_json)); 

EXIT:
    if (out_json)
        free(out_json);
}

void nanomq_set_auth_config(struct connection *cnn) {
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
    char *out_json = NULL;
#ifdef DEBUG	
	printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = mqtt_auth_set_cfg(in_json, &out_json);
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
    if (out_json)
        free(out_json);
    if (root)
        cJSON_Delete(root);
}


//iotdevmgr 

//通用 证书上传 查看

void iotdevmgr_get_iot_wrapper(struct connection *cnn)
{
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
    char *out_json = NULL;
#ifdef DEBUG    
    printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = iotdevmgr_get_iot(in_json, &out_json);
    if (ret != 0) {
        log_e("set cert and other failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        goto EXIT;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);

EXIT:
    FREE_ONCE(in_json);
    if (root)
        cJSON_Delete(root);
}


void iotdevmgr_del_iot_wrapper(struct connection *cnn)
{
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
    char *out_json = NULL;
#ifdef DEBUG    
    printf("Valid JSON Received:\n%s\n", in_json);
#endif
    int ret = iotdevmgr_del_iot(in_json, &out_json);
    if (ret != 0) {
        log_e("set cert and other failed");
        jrpc_send_error(cnn, JRPC_INTERNAL_ERROR, "internal error");
        FREE_ONCE(out_json);
        goto EXIT;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(out_json), NULL);
    http_response(cnn, out_json, strlen(out_json)); 
    FREE_ONCE(out_json);

EXIT:
    FREE_ONCE(in_json);
    if (root)
        cJSON_Delete(root);
}