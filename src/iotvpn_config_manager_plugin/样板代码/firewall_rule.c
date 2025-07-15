#include "firewall_rule.h"
#include "../../http_parser.h"
#include "../../server.h"
#include "../../utils.h"
#include "../../cJSON.h"
#include "../../Log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define RULE_NUM 512
#define FIREWALL_RULE_FILE "/opt/sslvpn/firewall_rule.conf"
#define MAX_CMD_LEN 128

// 安全字符串拷贝
#define SAFE_COPY(dest, src, max) do { \
        strncpy(dest, src, max - 1); \
        dest[max - 1] = '\0'; \
    } while(0)

typedef struct {
    //判断是否使用
    bool isused;
    char name[32];
    char description[64];
    char ip_range[32];
    char dst_ip[16];
    int port;
    char proto[4];
    bool status;
    bool isenable;
} FirewallRule;

FirewallRule *firewall_rule_list = NULL;

int firewall_rule_start()
{
    if (firewall_rule_list == NULL) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "防火墙规则列表未初始化", -1);
        return -1;
    }

    // 遍历规则列表，启用所有规则
    for (int i = 0; i < RULE_NUM; i++) {
        if (firewall_rule_list[i].isused && firewall_rule_list[i].isenable) {
            // 启用规则的逻辑
            char cmd[MAX_CMD_LEN] = {0};
            int len = snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -m iprange --src-range %s -d %s -p %s --dport %d -j %s",
                     firewall_rule_list[i].ip_range, firewall_rule_list[i].dst_ip,
                     firewall_rule_list[i].proto, firewall_rule_list[i].port, firewall_rule_list[i].status ? "ACCEPT" : "DROP");
            if (len < 0 || len >= sizeof(cmd)) {
                char message[MAX_CMD_LEN] = {0};
                snprintf(message, sizeof(message), "生成iptables命令失败，规则 %d", i);
                ccm_log(YXLOG_CCM_ERROR, "访问控制", message, -1);
                continue;
            }
            if (system(cmd) != 0) {
                char message[MAX_CMD_LEN] = {0};
                snprintf(message, sizeof(message), "执行iptables命令失败，规则 %d", i);
                ccm_log(YXLOG_CCM_ERROR, "访问控制", message, -1);
                continue;
            }
            char message[MAX_CMD_LEN] = {0};
            snprintf(message, sizeof(message), "启用防火墙规则 %s 成功", firewall_rule_list[i].name);
            ccm_log(YXLOG_CCM_INFO, "访问控制", message, 0);
        }
    }
    return 0;
}

int init_firewall_rule()
{
    int fd = open("/opt/sslvpn/firewall_rule.conf", O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "无法打开防火墙规则文件 /opt/sslvpn/firewall_rule.conf", -1);
        return -1;
    }

    // 获取当前文件大小
    struct stat st;
    if (fstat(fd, &st) < 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "获取防火墙规则文件大小失败", -1);
        close(fd);
        return -1;
    }

    // 如果文件是新创建的（大小为0）或大小不符合要求，则调整大小
    if (st.st_size == 0 || st.st_size != sizeof(FirewallRule) * RULE_NUM) {
        if (ftruncate(fd, sizeof(FirewallRule) * RULE_NUM) < 0) {
            ccm_log(YXLOG_CCM_ERROR, "访问控制", "调整防火墙规则文件大小失败", -1);
            close(fd);
            return -1;
        }
    }

    // 映射文件到内存
    firewall_rule_list = (FirewallRule *)mmap(NULL, sizeof(FirewallRule) * RULE_NUM, 
                                            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (firewall_rule_list == MAP_FAILED) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "映射防火墙规则文件失败", -1);
        close(fd);
        return -1;
    }
    close(fd);
    int ret = firewall_rule_start();
    return ret;
}

cJSON* get_sslvpn_firewall_rule()
{
    if (firewall_rule_list == NULL) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "防火墙规则列表未初始化", -1);
        return NULL;
    }

    cJSON *array = cJSON_CreateArray();
    if (NULL == array) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "创建防火墙规则 JSON 数组失败", -1);
        return NULL;
    }
// "fwconf": [
//    {
//        "key": 1,
//        "value": {
//            "name": "WEB",
//            "srciprange": "172.16.1.100-172.16.1.200",
//            "dstip": "192.168.10.20",
//            "dstport": 80,
//            "proto": "tcp",
//            "status": 0,
//            "description": "允许访问web",
//            "isenable": 1
//        }
//    },
//    {
//        "key": 1,
//        "value": ""
//    }
//]

    for (int i = 0; i < RULE_NUM; i++) {
        if (firewall_rule_list[i].isused) {
            cJSON *rule = cJSON_CreateObject();
            if (NULL == rule) {
                ccm_log(YXLOG_CCM_ERROR, "访问控制", "创建防火墙规则 JSON 对象失败", -1);
                cJSON_Delete(array);
                return NULL;
            }
            cJSON_AddNumberToObject(rule, "key", i);
            cJSON *value = cJSON_CreateObject();
            if (NULL == value) {
                ccm_log(YXLOG_CCM_ERROR, "访问控制", "创建防火墙规则值 JSON 对象失败", -1);
                cJSON_Delete(rule);
                cJSON_Delete(array);
                return NULL;
            }
            cJSON_AddStringToObject(value, "name", firewall_rule_list[i].name);
            cJSON_AddStringToObject(value, "srciprange", firewall_rule_list[i].ip_range);
            cJSON_AddStringToObject(value, "dstip", firewall_rule_list[i].dst_ip);
            cJSON_AddNumberToObject(value, "dstport", firewall_rule_list[i].port);
            cJSON_AddStringToObject(value, "proto", firewall_rule_list[i].proto);
            cJSON_AddBoolToObject(value, "status", firewall_rule_list[i].status);
            cJSON_AddStringToObject(value, "description", firewall_rule_list[i].description);
            cJSON_AddBoolToObject(value, "isenable", firewall_rule_list[i].isenable);

            // 将值对象添加到规则对象中
            cJSON_AddItemToObject(rule, "value", value);

            // 将规则对象添加到数组中
            cJSON_AddItemToArray(array, rule);
        }
        else {
            // 如果规则未使用，可以选择添加一个空对象或跳过
            cJSON *empty_rule = cJSON_CreateObject();
            if (NULL == empty_rule) {
                ccm_log(YXLOG_CCM_ERROR, "访问控制", "创建空防火墙规则 JSON 对象失败", -1);
                cJSON_Delete(array);
                return NULL;
            }
            cJSON_AddNumberToObject(empty_rule, "key", i);
            cJSON *empty_value = cJSON_CreateString("");
            if (NULL == empty_value) {
                ccm_log(YXLOG_CCM_ERROR, "访问控制", "创建空防火墙规则值 JSON 对象失败", -1);
                cJSON_Delete(empty_rule);
                cJSON_Delete(array);
                return NULL;
            }
            cJSON_AddItemToObject(empty_rule, "value", empty_value);
            // 将空规则对象添加到数组中
            cJSON_AddItemToArray(array, empty_rule);
        }
    }
    // 返回包含所有防火墙规则的 JSON 数组
    ccm_log(YXLOG_CCM_INFO, "访问控制", "获取防火墙规则成功", 0);
    cJSON *fwconf = cJSON_CreateObject();
    if (NULL == fwconf) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "创建防火墙规则 JSON 对象失败", -1);
        cJSON_Delete(array);
        return NULL;
    }
    cJSON_AddItemToObject(fwconf, "fwconf", array);

    return fwconf;
}

void get_firewall_rule(struct connection* cnn)
{
    struct http_str *ctype = http_get_header(cnn, "Content-Type");
    struct http_str *clen  = http_get_header(cnn, "Content-Length");
    
    if (ctype == NULL || clen == NULL) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "获取防火墙配置失败，缺少必要的请求头", -1);
        return;
    }
        
    ascii_dump("Content-Type", (char* )ctype->at, ctype->len);

    if (NULL == ctype) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "获取防火墙配置失败，Content-Type 为空", -1);
        return;
    }

    ascii_dump("Content-Length", (char* )clen->at, clen->len);

    struct http_str *body = &cnn->req.body;
    if (NULL == body) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "获取防火墙配置失败，Body 为空", -1);
        return;
    }
    ascii_dump("Body", (char* )body->at, body->len);

    cJSON* root = cJSON_ParseWithLength(body->at, body->len);
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "获取防火墙配置失败，JSON解析失败", -1);
        return;
    }

    cJSON_Delete(root);

    // 创建结果 JSON 对象
    cJSON *result = get_sslvpn_firewall_rule();
    if (NULL == result) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "获取防火墙配置失败，创建结果 JSON 对象失败", -1);
        return;
    }

    cJSON *res_root = cJSON_CreateObject();
    if (NULL == res_root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "获取防火墙配置失败，创建结果 JSON 对象失败", -1);
        cJSON_Delete(result);
        return;
    }

    // 添加结果到JSON对象
    cJSON_AddNumberToObject(res_root, "code", 0);
    cJSON_AddStringToObject(res_root, "message", "success");

    // 将解析后的对象添加到结果中
    cJSON_AddItemToObject(res_root, "result", result);
    
    char *json_str = cJSON_Print(res_root);
    if (NULL == json_str) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "获取防火墙配置失败，打印 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }

    http_response_head(cnn, HTTP_STATUS_OK, strlen(json_str), NULL);
    http_response(cnn, json_str, strlen(json_str));
    
    free(json_str);
    // 释放 JSON 对象
    cJSON_Delete(res_root);
}

int add_sslvpn_firewall_rule(cJSON *root)
{
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "设置系统日期时间失败，参数无效", -1);
        return -1;
    }
//{
//    "key": 1,
//    "value": {
//        "name": "WEB",
//        "srciprange": "172.16.1.100-172.16.1.200",
//        "dstip": "192.168.10.20",
//        "dstport": "80",
//        "proto": "tcp",
//        "status": 0,
//        "description": "允许访问web",
//        "isenable": 1
//    }
//}
    cJSON *key_item = cJSON_GetObjectItem(root, "key");
    cJSON *value_item = cJSON_GetObjectItem(root, "value");

    if (NULL == key_item || NULL == value_item) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，缺少 'key' 或 'value' 字段", -1);
        return -1;
    }

    int key = key_item->valueint;
    if (key < 0 || key >= RULE_NUM) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，key 超出范围", -1);
        return -1;
    }

    if (NULL == firewall_rule_list) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "防火墙规则列表未初始化", -1);
        return -1;
    }
    if (firewall_rule_list[key].isused) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，规则已存在", -1);
        return -1;
    }

    // 解析 value_item 中的字段
    cJSON *name_item = cJSON_GetObjectItem(value_item, "name");
    cJSON *srciprange_item = cJSON_GetObjectItem(value_item, "srciprange");
    cJSON *dstip_item = cJSON_GetObjectItem(value_item, "dstip");
    cJSON *dstport_item = cJSON_GetObjectItem(value_item, "dstport");
    cJSON *proto_item = cJSON_GetObjectItem(value_item, "proto");
    cJSON *status_item = cJSON_GetObjectItem(value_item, "status");
    cJSON *description_item = cJSON_GetObjectItem(value_item, "description");
    cJSON *isenable_item = cJSON_GetObjectItem(value_item, "isenable");

    if (NULL == name_item || NULL == srciprange_item || NULL == dstip_item ||
        NULL == dstport_item || NULL == proto_item || NULL == status_item ||
        NULL == description_item || NULL == isenable_item) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，缺少必要的字段", -1);
        return -1;
    }

    // 填充防火墙规则
    firewall_rule_list[key].isused = true;
    SAFE_COPY(firewall_rule_list[key].name, name_item->valuestring, sizeof(firewall_rule_list[key].name));
    SAFE_COPY(firewall_rule_list[key].ip_range, srciprange_item->valuestring, sizeof(firewall_rule_list[key].ip_range));
    SAFE_COPY(firewall_rule_list[key].dst_ip, dstip_item->valuestring, sizeof(firewall_rule_list[key].dst_ip));
    firewall_rule_list[key].port = dstport_item->valueint;
    SAFE_COPY(firewall_rule_list[key].proto, proto_item->valuestring, sizeof(firewall_rule_list[key].proto));
    firewall_rule_list[key].status = status_item->valueint;
    SAFE_COPY(firewall_rule_list[key].description, description_item->valuestring, sizeof(firewall_rule_list[key].description));
    firewall_rule_list[key].isenable = isenable_item->valueint;

    // 将规则写入文件
    if (msync(&firewall_rule_list[key], sizeof(FirewallRule), MS_SYNC) < 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "规则同步到磁盘失败", -1);
        return -1;
    }

    return 0;
}

void add_firewall_rule(struct connection* cnn)
{
    struct http_str *ctype = http_get_header(cnn, "Content-Type");
    struct http_str *clen  = http_get_header(cnn, "Content-Length");
    
    if (NULL == ctype || NULL == clen) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，缺少必要的请求头", -1);
        return;
    }
    
    ascii_dump("Content-Type", (char* )ctype->at, ctype->len);
    if (NULL == ctype) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，Content-Type 为空", -1);
        return;
    }
    ascii_dump("Content-Length", (char* )clen->at, clen->len);

    struct http_str *body = &cnn->req.body;
    if (NULL == body) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，请求体为空", -1);
        return;
    }
    ascii_dump("Body", (char* )body->at, body->len);

    cJSON* root = cJSON_ParseWithLength(body->at, body->len);
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，解析JSON失败", -1);
        return;
    }

    int ret = add_sslvpn_firewall_rule(root);
    if (ret) {
        ccm_log(YXLOG_CCM_INFO, "访问控制", "添加防火墙规则失败，写入文件失败", -1);
    }
#ifdef DEBUG
    char* str = cJSON_Print(root);
    printf("Valid JSON Received:\n%s\n", str);
    free(str);
#endif

    cJSON_Delete(root);

    cJSON *res_root = cJSON_CreateObject();
    if (NULL == res_root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，创建结果 JSON 对象失败", -1);
        return;
    }
    cJSON_AddNumberToObject(res_root, "code", ret);
    cJSON_AddStringToObject(res_root, "message", ret == 0 ? "success" : "failure");
    cJSON *result = cJSON_CreateObject();
    if (NULL == result) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，创建结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }

    cJSON_AddItemToObject(res_root, "result", result);
    char *res_str = cJSON_Print(res_root);
    if (NULL == res_str) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，打印结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }
    //printf("res=%s\n", res_str);

    http_response_head(cnn, HTTP_STATUS_OK, strlen(res_str), NULL);
    http_response(cnn, res_str, strlen(res_str));

    free(res_str);
    // 释放 JSON 对象
    cJSON_Delete(res_root);
}

int delete_sslvpn_firewall_rule(cJSON *root)
{
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，参数无效", -1);
        return -1;
    }

    cJSON *key_item = cJSON_GetObjectItem(root, "key");
    if (NULL == key_item) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，缺少 'key' 字段", -1);
        return -1;
    }

    int key = key_item->valueint;
    if (key < 0 || key >= RULE_NUM) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，key 超出范围", -1);
        return -1;
    }

    if (NULL == firewall_rule_list) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "防火墙规则列表未初始化", -1);
        return -1;
    }

    if (!firewall_rule_list[key].isused) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，规则不存在", -1);
        return -1;
    }

    if (firewall_rule_list[key].isenable){
        // 删除iptables规则
        char cmd[MAX_CMD_LEN] = {0};
        snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -m iprange --src-range %s -d %s -p %s --dport %d -j %s",
                 firewall_rule_list[key].ip_range, firewall_rule_list[key].dst_ip,
                 firewall_rule_list[key].proto, firewall_rule_list[key].port, 
                 firewall_rule_list[key].status ? "ACCEPT" : "DROP");
        if (system(cmd) != 0) {
            ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，执行iptables命令失败", -1);
            return -1;
        }
    }
    memset(&firewall_rule_list[key], 0, sizeof(FirewallRule));

    // 将规则写入文件
    if (msync(&firewall_rule_list[key], sizeof(FirewallRule), MS_SYNC) < 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "规则同步到磁盘失败", -1);
        return -1;
    }

    ccm_log(YXLOG_CCM_INFO, "访问控制", "删除防火墙规则成功", 0);
    return 0;
}

void delete_firewall_rule(struct connection* cnn)
{
    struct http_str *ctype = http_get_header(cnn, "Content-Type");
    struct http_str *clen  = http_get_header(cnn, "Content-Length");
    
    if (NULL == ctype || NULL == clen) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，缺少必要的请求头", -1);
        return;
    }
    
    ascii_dump("Content-Type", (char* )ctype->at, ctype->len);
    if (NULL == ctype) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，Content-Type 为空", -1);
        return;
    }
    ascii_dump("Content-Length", (char* )clen->at, clen->len);

    struct http_str *body = &cnn->req.body;
    if (NULL == body) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，请求体为空", -1);
        return;
    }
    ascii_dump("Body", (char* )body->at, body->len);

    cJSON* root = cJSON_ParseWithLength(body->at, body->len);
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，解析JSON失败", -1);
        return;
    }

    int ret = delete_sslvpn_firewall_rule(root);
    if (ret) {
        ccm_log(YXLOG_CCM_INFO, "访问控制", "删除防火墙规则失败，写入文件失败", -1);
    }
#ifdef DEBUG
    char* str = cJSON_Print(root);
    printf("Valid JSON Received:\n%s\n", str);
    free(str);
#endif

    cJSON_Delete(root);

    cJSON *res_root = cJSON_CreateObject();
    if (NULL == res_root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，创建结果 JSON 对象失败", -1);
        return;
    }
    cJSON_AddNumberToObject(res_root, "code", ret);
    cJSON_AddStringToObject(res_root, "message", ret == 0 ? "success" : "failure");
    cJSON *result = cJSON_CreateObject();
    if (NULL == result) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，创建结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }

    cJSON_AddItemToObject(res_root, "result", result);
    char *res_str = cJSON_Print(res_root);
    if (NULL == res_str) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，打印结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }
    //printf("res=%s\n", res_str);

    http_response_head(cnn, HTTP_STATUS_OK, strlen(res_str), NULL);
    http_response(cnn, res_str, strlen(res_str));

    free(res_str);
    // 释放 JSON 对象
    cJSON_Delete(res_root);
}

int modify_sslvpn_firewall_rule(cJSON *root)
{
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，参数无效", -1);
        return -1;
    }

    cJSON *key_item = cJSON_GetObjectItem(root, "key");
    cJSON *value_item = cJSON_GetObjectItem(root, "value");
    if (NULL == key_item || NULL == value_item) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，缺少 'key' 或 'value' 字段", -1);
        return -1;
    }

    int key = key_item->valueint;
    if (key < 0 || key >= RULE_NUM) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，key 超出范围", -1);
        return -1;
    }

    if (NULL == firewall_rule_list) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "防火墙规则列表未初始化", -1);
        return -1;
    }

    if (!firewall_rule_list[key].isused)
    {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，规则不存在", -1);
        return -1;
    }

    if (firewall_rule_list[key].isenable){
        // 删除iptables规则
        char cmd[MAX_CMD_LEN] = {0};
        snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -m iprange --src-range %s -d %s -p %s --dport %d -j %s",
                 firewall_rule_list[key].ip_range, firewall_rule_list[key].dst_ip,
                 firewall_rule_list[key].proto, firewall_rule_list[key].port, 
                 firewall_rule_list[key].status ? "ACCEPT" : "DROP");
        if (system(cmd) != 0) {
            ccm_log(YXLOG_CCM_ERROR, "访问控制", "删除防火墙规则失败，执行iptables命令失败", -1);
            return -1;
        }
    }

    // 解析 value_item 中的字段
    cJSON *name_item = cJSON_GetObjectItem(value_item, "name");
    cJSON *srciprange_item = cJSON_GetObjectItem(value_item, "srciprange");
    cJSON *dstip_item = cJSON_GetObjectItem(value_item, "dstip");
    cJSON *dstport_item = cJSON_GetObjectItem(value_item, "dstport");
    cJSON *proto_item = cJSON_GetObjectItem(value_item, "proto");
    cJSON *status_item = cJSON_GetObjectItem(value_item, "status");
    cJSON *description_item = cJSON_GetObjectItem(value_item, "description");
    cJSON *isenable_item = cJSON_GetObjectItem(value_item, "isenable");

    if (NULL == name_item || NULL == srciprange_item || NULL == dstip_item ||
        NULL == dstport_item || NULL == proto_item || NULL == status_item ||
        NULL == description_item || NULL == isenable_item) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "添加防火墙规则失败，缺少必要的字段", -1);
        return -1;
    }

    // 填充防火墙规则
    firewall_rule_list[key].isused = true;
    SAFE_COPY(firewall_rule_list[key].name, name_item->valuestring, sizeof(firewall_rule_list[key].name));
    SAFE_COPY(firewall_rule_list[key].ip_range, srciprange_item->valuestring, sizeof(firewall_rule_list[key].ip_range));
    SAFE_COPY(firewall_rule_list[key].dst_ip, dstip_item->valuestring, sizeof(firewall_rule_list[key].dst_ip));
    firewall_rule_list[key].port = dstport_item->valueint;
    SAFE_COPY(firewall_rule_list[key].proto, proto_item->valuestring, sizeof(firewall_rule_list[key].proto));
    firewall_rule_list[key].status = status_item->valueint;
    SAFE_COPY(firewall_rule_list[key].description, description_item->valuestring, sizeof(firewall_rule_list[key].description));
    firewall_rule_list[key].isenable = 0;

    // 将规则写入文件
    if (msync(&firewall_rule_list[key], sizeof(FirewallRule), MS_SYNC) < 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "规则同步到磁盘失败", -1);
        return -1;
    }

    ccm_log(YXLOG_CCM_INFO, "访问控制", "修改防火墙规则成功", 0);

    return 0;
}

void modify_firewall_rule(struct connection* cnn)
{
    struct http_str *ctype = http_get_header(cnn, "Content-Type");
    struct http_str *clen  = http_get_header(cnn, "Content-Length");
    
    if (NULL == ctype || NULL == clen) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，缺少必要的请求头", -1);
        return;
    }
    
    ascii_dump("Content-Type", (char* )ctype->at, ctype->len);
    if (NULL == ctype) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，Content-Type 为空", -1);
        return;
    }
    ascii_dump("Content-Length", (char* )clen->at, clen->len);

    struct http_str *body = &cnn->req.body;
    if (NULL == body) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，请求体为空", -1);
        return;
    }
    ascii_dump("Body", (char* )body->at, body->len);

    cJSON* root = cJSON_ParseWithLength(body->at, body->len);
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，解析JSON失败", -1);
        return;
    }

    int ret = modify_sslvpn_firewall_rule(root);
    if (ret) {
        ccm_log(YXLOG_CCM_INFO, "访问控制", "修改防火墙规则失败，写入文件失败", -1);
    }
#ifdef DEBUG
    char* str = cJSON_Print(root);
    printf("Valid JSON Received:\n%s\n", str);
    free(str);
#endif

    cJSON_Delete(root);

    cJSON *res_root = cJSON_CreateObject();
    if (NULL == res_root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，创建结果 JSON 对象失败", -1);
        return;
    }
    cJSON_AddNumberToObject(res_root, "code", ret);
    cJSON_AddStringToObject(res_root, "message", ret == 0 ? "success" : "failure");
    cJSON *result = cJSON_CreateObject();
    if (NULL == result) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，创建结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }

    cJSON_AddItemToObject(res_root, "result", result);
    char *res_str = cJSON_Print(res_root);
    if (NULL == res_str) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "修改防火墙规则失败，打印结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }
    //printf("res=%s\n", res_str);

    http_response_head(cnn, HTTP_STATUS_OK, strlen(res_str), NULL);
    http_response(cnn, res_str, strlen(res_str));

    free(res_str);
    // 释放 JSON 对象
    cJSON_Delete(res_root);
}

int start_sslvpn_firewall_rule(cJSON *root)
{
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，参数无效", -1);
        return -1;
    }

    cJSON *key_item = cJSON_GetObjectItem(root, "key");
    if (NULL == key_item) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，缺少 'key' 字段", -1);
        return -1;
    }

    int key = key_item->valueint;
    if (key < 0 || key >= RULE_NUM) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，key 超出范围", -1);
        return -1;
    }

    if (NULL == firewall_rule_list) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "防火墙规则列表未初始化", -1);
        return -1;
    }

    if (!firewall_rule_list[key].isused) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，规则不存在", -1);
        return -1;
    }

    if (firewall_rule_list[key].isenable) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，规则已启用", -1);
        return -1;
    }

    char cmd[MAX_CMD_LEN] = {0};
    snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -m iprange --src-range %s -d %s -p %s --dport %d -j %s",
             firewall_rule_list[key].ip_range, firewall_rule_list[key].dst_ip,
             firewall_rule_list[key].proto, firewall_rule_list[key].port, 
             firewall_rule_list[key].status ? "ACCEPT" : "DROP");

    if (system(cmd) != 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，执行iptables命令失败", -1);
        return -1;
    }

    firewall_rule_list[key].isenable = 1;

    // 将规则写入文件
    if (msync(&firewall_rule_list[key], sizeof(FirewallRule), MS_SYNC) < 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "规则同步到磁盘失败", -1);
        return -1;
    }

    ccm_log(YXLOG_CCM_INFO, "访问控制", "启动防火墙规则成功", 0);
    return 0;
}

void start_firewall_rule(struct connection* cnn)
{
    struct http_str *ctype = http_get_header(cnn, "Content-Type");
    struct http_str *clen  = http_get_header(cnn, "Content-Length");
    
    if (NULL == ctype || NULL == clen) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，缺少必要的请求头", -1);
        return;
    }
    
    ascii_dump("Content-Type", (char* )ctype->at, ctype->len);
    if (NULL == ctype) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，Content-Type 为空", -1);
        return;
    }
    ascii_dump("Content-Length", (char* )clen->at, clen->len);

    struct http_str *body = &cnn->req.body;
    if (NULL == body) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，请求体为空", -1);
        return;
    }
    ascii_dump("Body", (char* )body->at, body->len);

    cJSON* root = cJSON_ParseWithLength(body->at, body->len);
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，解析JSON失败", -1);
        return;
    }

    int ret = start_sslvpn_firewall_rule(root);
    if (ret) {
        ccm_log(YXLOG_CCM_INFO, "访问控制", "启动防火墙规则失败，写入文件失败", -1);
    }
#ifdef DEBUG
    char* str = cJSON_Print(root);
    printf("Valid JSON Received:\n%s\n", str);
    free(str);
#endif

    cJSON_Delete(root);

    cJSON *res_root = cJSON_CreateObject();
    if (NULL == res_root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，创建结果 JSON 对象失败", -1);
        return;
    }
    cJSON_AddNumberToObject(res_root, "code", ret);
    cJSON_AddStringToObject(res_root, "message", ret == 0 ? "success" : "failure");
    cJSON *result = cJSON_CreateObject();
    if (NULL == result) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，创建结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }

    cJSON_AddItemToObject(res_root, "result", result);
    char *res_str = cJSON_Print(res_root);
    if (NULL == res_str) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "启动防火墙规则失败，打印结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }
    //printf("res=%s\n", res_str);

    http_response_head(cnn, HTTP_STATUS_OK, strlen(res_str), NULL);
    http_response(cnn, res_str, strlen(res_str));

    free(res_str);
    // 释放 JSON 对象
    cJSON_Delete(res_root);
}

int stop_sslvpn_firewall_rule(cJSON *root)
{
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，参数无效", -1);
        return -1;
    }

    cJSON *key_item = cJSON_GetObjectItem(root, "key");
    if (NULL == key_item) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，缺少 'key' 字段", -1);
        return -1;
    }

    int key = key_item->valueint;
    if (key < 0 || key >= RULE_NUM) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，key 超出范围", -1);
        return -1;
    }

    if (NULL == firewall_rule_list) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "防火墙规则列表未初始化", -1);
        return -1;
    }

    if (!firewall_rule_list[key].isused) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，规则不存在", -1);
        return -1;
    }

    if (!firewall_rule_list[key].isenable) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，规则未启用", -1);
        return -1;
    }

    char cmd[MAX_CMD_LEN] = {0};
    snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -m iprange --src-range %s -d %s -p %s --dport %d -j %s",
             firewall_rule_list[key].ip_range, firewall_rule_list[key].dst_ip,
             firewall_rule_list[key].proto, firewall_rule_list[key].port, 
             firewall_rule_list[key].status ? "ACCEPT" : "DROP");

    if (system(cmd) != 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，执行iptables命令失败", -1);
        return -1;
    }

    firewall_rule_list[key].isenable = 0;

    // 将规则写入文件
    if (msync(&firewall_rule_list[key], sizeof(FirewallRule), MS_SYNC) < 0) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "规则同步到磁盘失败", -1);
        return -1;
    }

    ccm_log(YXLOG_CCM_INFO, "访问控制", "停止防火墙规则成功", 0);
    return 0;
}

void stop_firewall_rule(struct connection* cnn)
{
    struct http_str *ctype = http_get_header(cnn, "Content-Type");
    struct http_str *clen  = http_get_header(cnn, "Content-Length");
    
    if (NULL == ctype || NULL == clen) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，缺少必要的请求头", -1);
        return;
    }
    
    ascii_dump("Content-Type", (char* )ctype->at, ctype->len);
    if (NULL == ctype) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，Content-Type 为空", -1);
        return;
    }
    ascii_dump("Content-Length", (char* )clen->at, clen->len);

    struct http_str *body = &cnn->req.body;
    if (NULL == body) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，请求体为空", -1);
        return;
    }
    ascii_dump("Body", (char* )body->at, body->len);

    cJSON* root = cJSON_ParseWithLength(body->at, body->len);
    if (NULL == root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，解析JSON失败", -1);
        return;
    }

    int ret = stop_sslvpn_firewall_rule(root);
    if (ret) {
        ccm_log(YXLOG_CCM_INFO, "访问控制", "停止防火墙规则失败，写入文件失败", -1);
    }
#ifdef DEBUG
    char* str = cJSON_Print(root);
    printf("Valid JSON Received:\n%s\n", str);
    free(str);
#endif

    cJSON_Delete(root);

    cJSON *res_root = cJSON_CreateObject();
    if (NULL == res_root) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，创建结果 JSON 对象失败", -1);
        return;
    }
    cJSON_AddNumberToObject(res_root, "code", ret);
    cJSON_AddStringToObject(res_root, "message", ret == 0 ? "success" : "failure");
    cJSON *result = cJSON_CreateObject();
    if (NULL == result) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，创建结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }

    cJSON_AddItemToObject(res_root, "result", result);
    char *res_str = cJSON_Print(res_root);
    if (NULL == res_str) {
        ccm_log(YXLOG_CCM_ERROR, "访问控制", "停止防火墙规则失败，打印结果 JSON 对象失败", -1);
        cJSON_Delete(res_root);
        return;
    }
    //printf("res=%s\n", res_str);

    http_response_head(cnn, HTTP_STATUS_OK, strlen(res_str), NULL);
    http_response(cnn, res_str, strlen(res_str));

    free(res_str);
    // 释放 JSON 对象
    cJSON_Delete(res_root);
}