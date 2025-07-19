package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"encoding/json"
	"iotvpn_config_manager_plugin/sslvpn/pkg/api"
	"iotvpn_config_manager_plugin/sslvpn/pkg/types"
)

func handleAPICall(
	in_json *C.char,
	out_json **C.char,
	apiFunc func(string) (*types.BaseResponse, error),
) C.int {
	inputStr := ""
	if in_json != nil {
		inputStr = C.GoString(in_json)
	}

	result, _ := apiFunc(inputStr)

	responseJSON, _ := json.Marshal(result)
	allocateAndSetCString(string(responseJSON), out_json)
	return C.int(result.Code)
}

//export sslvpn_get_version
func sslvpn_get_version(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.GetVersion)
}

//export sslvpn_check_status
func sslvpn_check_status(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.CheckStatus)
}

//export sslvpn_gen_default_cfg
func sslvpn_gen_default_cfg(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.GenerateDefaultConfig)
}

//export sslvpn_restart_service
func sslvpn_restart_service(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.RestartService)
}

//export sslvpn_set_cfg
func sslvpn_set_cfg(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.SetConfig)
}

//export sslvpn_get_cfg
func sslvpn_get_cfg(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.GetConfig)
}

//export sslvpn_set_user
func sslvpn_set_user(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.SetUser)
}

//export sslvpn_get_user
func sslvpn_get_user(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.GetUser)
}

//export sslvpn_set_resource
func sslvpn_set_resource(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.SetResource)
}

//export sslvpn_get_resource
func sslvpn_get_resource(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.GetResource)
}

//export sslvpn_set_authority
func sslvpn_set_authority(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.SetAuthority)
}

//export sslvpn_get_authority
func sslvpn_get_authority(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.GetAuthority)
}

//export plugin_set_cert_and_other
func plugin_set_cert_and_other(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.SetCertAndOther)
}

//export plugin_get_cert_and_other
func plugin_get_cert_and_other(in_json *C.char, out_json **C.char) C.int {
	return handleAPICall(in_json, out_json, api.GetCertAndOther)
}

// 辅助函数：分配C字符串内存并设置指针
func allocateAndSetCString(src string, dst **C.char) {
	if dst != nil {
		cStr := C.CString(src)
		*dst = cStr
	}
}
