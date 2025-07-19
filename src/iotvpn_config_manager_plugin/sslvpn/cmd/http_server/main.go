package main

/*
#cgo CFLAGS: -I../../include
#cgo LDFLAGS: -L../../../release/lib -lsslvpn
#include <stdlib.h>
#include <string.h>
#include "sslvpn_api.h"

// 定义一个函数类型，用于Go中转换C函数指针
typedef int (*ssl_vpn_func_t)(const char*, char**);

// 包装C函数，使其可以从Go中调用
static int call_ssl_vpn_func(ssl_vpn_func_t f, const char* in_json, char** out_json) {
    return f(in_json, out_json);
}
*/
import "C"

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"unsafe"
)

func main() {
	// 注册HTTP处理函数
	http.HandleFunc("/ccm/v1/manage/sslvpn/check-status", handleStatus)
	http.HandleFunc("/ccm/v1/manage/sslvpn/gendefault-cfg", handleDefaultConfig)
	http.HandleFunc("/ccm/v1/manage/sslvpn/restart-service", handleRestart)
	http.HandleFunc("/ccm/v1/manage/sslvpn/set-cfg", handleSetConfig)
	http.HandleFunc("/ccm/v1/manage/sslvpn/get-cfg", handleGetConfig)
	http.HandleFunc("/ccm/v1/manage/sslvpn/set-user", handleSetUser)
	http.HandleFunc("/ccm/v1/manage/sslvpn/get-user", handleGetUser)
	http.HandleFunc("/ccm/v1/manage/sslvpn/set-resource", handleSetResource)
	http.HandleFunc("/ccm/v1/manage/sslvpn/get-resource", handleGetResource)
	http.HandleFunc("/ccm/v1/manage/sslvpn/set-authority", handleSetAuthority)
	http.HandleFunc("/ccm/v1/manage/sslvpn/get-authority", handleGetAuthority)

	http.HandleFunc("/ccm/v1/manage/plugin/set-cert", handleSetCertAndOther)
	http.HandleFunc("/ccm/v1/manage/plugin/get-cert", handleGetCertAndOther)

	// 启动HTTP服务器
	port := 8080
	log.Printf("HTTP服务器启动在 :%d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

// 处理状态请求
func handleStatus(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_check_status))
}

// 处理默认配置请求
func handleDefaultConfig(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_gen_default_cfg))
}

// 处理重启服务请求
func handleRestart(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_restart_service))
}

// 处理设置配置请求
func handleSetConfig(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_set_cfg))
}

// 处理获取配置请求
func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_get_cfg))
}

// 处理设置用户请求
func handleSetUser(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_set_user))
}

// 处理获取用户请求
func handleGetUser(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_get_user))
}

// 处理设置资源请求
func handleSetResource(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_set_resource))
}

// 处理获取资源请求
func handleGetResource(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_get_resource))
}

// 处理设置权限请求
func handleSetAuthority(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_set_authority))
}

// 处理获取权限请求
func handleGetAuthority(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.sslvpn_get_authority))
}

// 处理设置权限请求
func handleSetCertAndOther(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.plugin_set_cert_and_other))
}

// 处理获取权限请求
func handleGetCertAndOther(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, C.ssl_vpn_func_t(C.plugin_get_cert_and_other))
}

// 通用请求处理函数
func handleRequest(w http.ResponseWriter, r *http.Request, cFunc C.ssl_vpn_func_t) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "读取请求体失败", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// 准备C函数参数
	cInput := C.CString(string(body))
	defer C.free(unsafe.Pointer(cInput))

	var cOutput *C.char
	defer func() {
		if cOutput != nil {
			C.free(unsafe.Pointer(cOutput))
		}
	}()

	// 调用C函数
	ret := C.call_ssl_vpn_func(cFunc, cInput, &cOutput)

	// 处理响应
	response := C.GoString(cOutput)

	w.Header().Set("Content-Type", "application/json")
	if ret != 0 {
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Write([]byte(response))
}
