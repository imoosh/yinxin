#ifndef __LIBIOTVPN_PLUGIN_WRAPPER_H__
#define __LIBIOTVPN_PLUGIN_WRAPPER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>

#include <ev.h>
#include "buff.h"
#include "http_parser.h"
#include "server.h"
#include "utils.h"

#include "cJSON.h"



//通用 证书上传 查看
void plugin_get_cert_and_other_wrapper(struct connection *cnn);
void plugin_set_cert_and_other_wrapper(struct connection *cnn);

// restart_sslvpn_service 重启sslvpn服务
void restart_sslvpn_service_wrapper(struct connection *cnn);

// get_sslvpn_status 获取sslvpn服务状态
void get_sslvpn_status_wrapper(struct connection *cnn);

// get_sslvpn_config 获取sslvpn服务配置
void get_sslvpn_config_wrapper(struct connection *cnn);

// set_sslvpn_config 设置sslvpn服务配置
void set_sslvpn_config_wrapper(struct connection *cnn);

// sslvpn_set_user 设置用户
void sslvpn_set_user_wrapper(struct connection *cnn);

// sslvpn_get_user 获取用户
void sslvpn_get_user_wrapper(struct connection *cnn);

// sslvpn_set_resource 设置资源
void sslvpn_set_resource_wrapper(struct connection *cnn);

// sslvpn_get_resource 获取资源
void sslvpn_get_resource_wrapper(struct connection *cnn);

// sslvpn_set_authority 设置权限
void sslvpn_set_authority_wrapper(struct connection *cnn);

// sslvpn_get_authority 获取权限
void sslvpn_get_authority_wrapper(struct connection *cnn);

// nanomq =======////////////////////
void nanomq_restart_service(struct connection *cnn);
void nanomq_check_status(struct connection *cnn);
void nanomq_get_service_config(struct connection *cnn);
void nanomq_set_service_config(struct connection *cnn);
void nanomq_get_auth_config(struct connection *cnn);
void nanomq_set_auth_config(struct connection *cnn);



//iot设备管理
void iotdevmgr_get_iot_wrapper(struct connection *cnn);
void iotdevmgr_del_iot_wrapper(struct connection *cnn);

#ifdef __cplusplus
}
#endif

#endif
