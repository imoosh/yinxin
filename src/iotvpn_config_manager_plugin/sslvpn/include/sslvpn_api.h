#ifndef SSLVPN_API_H
#define SSLVPN_API_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 获取版本信息
 * @param in_json 输入JSON字符串（空字符串即可）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_get_version(const char* in_json, char** out_json);

/**
 * @brief 检查VPN服务状态
 * @param in_json 输入JSON字符串（空字符串即可）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_check_status(const char* in_json, char** out_json);

/**
 * @brief 生成默认配置/恢复默认配置
 * @param in_json 输入JSON字符串（空字符串即可）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_gen_default_cfg(const char* in_json, char** out_json);

/**
 * @brief 重启VPN服务
 * @param in_json 输入JSON字符串（空字符串即可）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_restart_service(const char* in_json, char** out_json);

/**
 * @brief 设置VPN配置参数
 * @param in_json 输入JSON字符串（包含VPN配置）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_set_cfg(const char* in_json, char** out_json);

/**
 * @brief 查询VPN配置参数
 * @param in_json 输入JSON字符串（空字符串即可）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_get_cfg(const char* in_json, char** out_json);

/**
 * @brief 设置用户信息
 * @param in_json 输入JSON字符串（用户数组）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_set_user(const char* in_json, char** out_json);

/**
 * @brief 查询用户信息
 * @param in_json 输入JSON字符串（空字符串即可）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_get_user(const char* in_json, char** out_json);

/**
 * @brief 设置资源信息
 * @param in_json 输入JSON字符串（资源数组）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_set_resource(const char* in_json, char** out_json);

/**
 * @brief 查询资源信息
 * @param in_json 输入JSON字符串（空字符串即可）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_get_resource(const char* in_json, char** out_json);

/**
 * @brief 设置权限规则
 * @param in_json 输入JSON字符串（权限配置）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_set_authority(const char* in_json, char** out_json);

/**
 * @brief 查询权限规则
 * @param in_json 输入JSON字符串（空字符串即可）
 * @param out_json 输出JSON字符串指针（函数内部分配内存，调用者需要使用free释放）
 * @return 0成功，非0失败
 */
int sslvpn_get_authority(const char* in_json, char** out_json);

int plugin_set_cert_and_other(const char* in_json, char** out_json);

int plugin_get_cert_and_other(const char* in_json, char** out_json);

#ifdef __cplusplus
}
#endif

#endif // SSLVPN_API_H 