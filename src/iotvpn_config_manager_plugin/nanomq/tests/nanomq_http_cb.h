#ifndef __NANOMQ_HTTP_CB_H__
#define __NANOMQ_HTTP_CB_H__

#include <stdio.h>
#include <stdlib.h>

#include <ev.h>
#include "buff.h"
#include "http_parser.h"
#include "server.h"
#include "utils.h"

#include "cJSON.h"

#include "libnanomq.h"

// restart_nanomq_service 重启nanomq服务
void restart_nanomq_service(struct connection *cnn);

// get_nanomq_status 获取nanomq服务状态
void get_nanomq_status(struct connection *cnn);

// get_nanomq_config 获取nanomq服务配置
void get_nanomq_config(struct connection *cnn);

// set_nanomq_config 设置nanomq服务配置
void set_nanomq_config(struct connection *cnn);

// get_mqtt_auth_config 获取mqtt认证配置
void get_mqtt_auth_config(struct connection *cnn);

// set_mqtt_auth_config 设置mqtt认证配置
void set_mqtt_auth_config(struct connection *cnn);

#endif
