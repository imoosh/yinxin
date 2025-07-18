package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L.
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// 定义返回错误的结构体
typedef struct {
    char* message;
    int code;
} Error;

// 分配内存的辅助函数
//char* allocate_string(size_t size) {
    //return (char*)malloc(size);
//}

//// 释放内存的辅助函数
//void free_string(char* str) {
    //free(str);
//}
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"unsafe"
)

const (
	NANOMQ_PID_FILE   = "/tmp/nanomq/nanomq.pid"
	NANOMQ_ETC_CONFIG = "/etc/nanomq_old.conf"
)

var (
	ErrInvalidInputParam      = errors.New("invalid input param")
	ErrInvalidJsonFormat      = errors.New("invalid json format")
	ErrLoadNanoMQConfigFailed = errors.New("load nanomq config failed")
	ErrJsonMarshalFailed      = errors.New("json marshal failed")
	ErrJsonUnmarshalFailed    = errors.New("json unmarshal failed")

	nanomqLogLevel = map[string]interface{}{
		"trace": nil,
		"debug": nil,
		"info":  nil,
		"warn":  nil,
		"error": nil,
		"fatal": nil,
	}

	ResultErr = &httpResult{
		Code:    -1,
		Message: "plugin internal error",
		Result:  struct{}{},
	}
	ResultOK = &httpResult{
		Code:    0,
		Message: "success",
		Result:  struct{}{},
	}
)

type nanomqListenersSSL struct {
	Port       int  `json:"port"`
	VerifyPeer bool `json:"verify_peer"`
}

type nanomqHttpServer struct {
	Port int `json:"port"`
}

type nanomqLog struct {
	Level string `json:"level"`
}

type nanomqServiceConfig struct {
	ListenersSSL nanomqListenersSSL `json:"listeners.ssl"`
	HttpServer   nanomqHttpServer   `json:"http_server"`
	Log          nanomqLog          `json:"log"`
}

type mqttLoginAuth struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type mqttACLRule struct {
	Id     int    `json:"id"`
	Permit string `json:"permit,omitempty"`
	// ipaddr,clientid,username 三选一
	Username string `json:"username,omitempty"`
	IPAddr   string `json:"ipaddr,omitempty"`
	ClientID string `json:"clientid,omitempty"`

	Action string   `json:"action,omitempty"`
	Topics []string `json:"topics,omitempty"`
}

type mqttAuthACLConfig struct {
	LoginAuth []mqttLoginAuth `json:"login_auth"`
	ACLRule   []mqttACLRule   `json:"acl_rule"`
}

type httpResult struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Result  interface{} `json:"result"`
}

func (result *httpResult) String() string {
	if result.Result == nil {
		result.Result = struct{}{}
	}
	data, err := json.Marshal(result)
	if err != nil {
		LogError("json.Marshal error: %v", err)
		return ResultErr.String()
	}
	return string(data)
}
func (result *httpResult) Copy(from *httpResult) *httpResult {
	*result = *from
	return result
}

// 装载处理结果
func (result *httpResult) Load(out *C.char) C.int {
	if out == nil {
		return -1
	}
	var (
		str    = result.String()
		length = len(str)
		bytes  = []byte(str)
	)
	// 拷贝字符串
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&bytes[0]), C.size_t(length))

	// 追加字符串结束符
	endptr := (*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(out)) + uintptr(length)))
	*endptr = 0

	return 0
}

//export nanomq_get_cfg
func nanomq_get_cfg(in_json, out_json *C.char) (ret C.int) {
	var result = httpResult{Code: -1}
	defer func() {
		ret = result.Load(out_json)
	}()

	if out_json == nil {
		result.Message = ErrInvalidInputParam.Error()
		return -1
	}

	nmc, err := NewNanoMQConfig(NANOMQ_ETC_CONFIG)
	if err != nil {
		LogError(err.Error())
		result.Message = ErrLoadNanoMQConfigFailed.Error()
		return -1
	}
	nmc.Parse()

	var c nanomqServiceConfig
	c.ListenersSSL.Port = nmc.TLSPort
	c.ListenersSSL.VerifyPeer = nmc.TLSVerifyPeer
	c.HttpServer.Port = nmc.HTTPServerPort
	c.Log.Level = nmc.LogLevel

	result.Copy(ResultOK).Result = &c

	return 0
}

func nanomq_set_cfg_check_param(conf *nanomqServiceConfig) error {
	if conf.HttpServer.Port <= 0 || conf.HttpServer.Port >= 65536 {
		return fmt.Errorf("Invalid nanomq service paramater: nanomq http server port must be [0,65535]")
	}
	if conf.ListenersSSL.Port <= 0 || conf.ListenersSSL.Port >= 65536 {
		return fmt.Errorf("Invalid nanomq service paramater: nanomq ssl port must be [0,65535]")
	}
	if _, ok := nanomqLogLevel[conf.Log.Level]; !ok {
		return fmt.Errorf("Invalid nanomq service paramater: nanomq log level must be [trace, debug, info, warn, error, fatal]")
	}

	return nil
}

//export nanomq_set_cfg
func nanomq_set_cfg(in_json, out_json *C.char) (ret C.int) {
	var result = httpResult{Code: -1}

	defer func() {
		ret = result.Load(out_json)
	}()

	if in_json == nil || out_json == nil {
		LogError(ErrInvalidInputParam.Error())
		result.Message = ErrInvalidInputParam.Error()
		return -1
	}

	in_str := C.GoString(in_json)
	LogDebug("in_json: %s\n", in_str)

	// 解析当前配置文件
	var c nanomqServiceConfig
	err := json.Unmarshal([]byte(in_str), &c)
	if err != nil {
		LogError(ErrInvalidJsonFormat.Error())
		result.Message = ErrInvalidJsonFormat.Error()
		return -1
	}

	if err := nanomq_set_cfg_check_param(&c); err != nil {
		LogError(err.Error())
		result.Message = err.Error()
		return -1
	}

	nmc, err := NewNanoMQConfig(NANOMQ_ETC_CONFIG)
	if err != nil {
		LogError("new nanomq config error: %v\n", err)
		result.Message = ErrLoadNanoMQConfigFailed.Error()
		return -1
	}
	nmc.Parse()

	// 更新配置缓存
	nmc.TLSPort = c.ListenersSSL.Port
	nmc.TLSUrl = nmc.TLSPortPrefix + ":" + fmt.Sprint(nmc.TLSPort)
	nmc.TLSVerifyPeer = c.ListenersSSL.VerifyPeer
	nmc.HTTPServerPort = c.HttpServer.Port
	nmc.LogLevel = c.Log.Level

	// 同步配置文件
	err = nmc.Sync()
	if err != nil {
		result.Message = err.Error()
	} else {
		result.Copy(ResultOK)
	}
	return 0
}

//export mqtt_auth_get_cfg
func mqtt_auth_get_cfg(in_json, out_json *C.char) (ret C.int) {
	var result = httpResult{Code: -1}

	defer func() {
		ret = result.Load(out_json)
	}()

	if out_json == nil {
		result.Message = ErrInvalidInputParam.Error()
		return -1
	}

	nmc, err := NewNanoMQConfig(NANOMQ_ETC_CONFIG)
	if err != nil {
		LogError("new nanomq config error: %v\n", err)
		result.Message = ErrLoadNanoMQConfigFailed.Error()
		return -1
	}
	nmc.Parse()

	var c mqttAuthACLConfig
	for id, item := range nmc.AuthLoginList {
		c.LoginAuth = append(c.LoginAuth, mqttLoginAuth{
			Id:       id + 1,
			Username: item.Login,
			Password: item.Password,
		})
	}
	for id, item := range nmc.ACLConf.ACLRuleList {
		c.ACLRule = append(c.ACLRule, mqttACLRule{
			Id:       id + 1,
			Permit:   item.Permit,
			Username: item.Username,
			Action:   item.Action,
			Topics:   item.Topics,
		})
	}

	result.Copy(ResultOK).Result = &c

	return 0
}

func mqtt_auth_set_cfg_check_param(conf *mqttAuthACLConfig) error {
	for idx, item := range conf.LoginAuth {
        fmt.Printf("login_auth ==> idx=%d, id=%d\n",idx+1, item.Id)
		if item.Id != idx+1 {
			return fmt.Errorf("Invalid login auth paramater: id is wrong")
		}
		if item.Username == "" || item.Password == "" {
			return fmt.Errorf("Invalid login auth paramater: username or password is empty")
		}
	}

	for idx, item := range conf.ACLRule {
        fmt.Printf("acl_rule   ==> idx=%d, id=%d\n",idx+1, item.Id)
		if item.Id != idx+1 {
			return fmt.Errorf("Invalid ACL rule paramater: id is wrong")
		}
		if item.Permit != "allow" && item.Permit != "deny" {
			return fmt.Errorf("Invalid ACL rule paramater: permit must be 'allow' or 'deny'")
		}
		if item.Action != "" && item.Action != "subscribe" && item.Action != "publish" && item.Action != "pubsub" {
			return fmt.Errorf("Invalid ACL rule paramater: action must be subscribe/publish/pubsub or empty")
		}
	}

	return nil
}

//export mqtt_auth_set_cfg
func mqtt_auth_set_cfg(in_json, out_json *C.char) (ret C.int) {
	var result = httpResult{Code: -1}

	defer func() {
		ret = result.Load(out_json)
	}()

	if in_json == nil || out_json == nil {
		LogError(ErrInvalidInputParam.Error())
        result.Message = ErrInvalidInputParam.Error()
		return -1
	}

	in_str := C.GoString(in_json)
	LogDebug("in_json: %s\n", in_str)

	// 解析当前配置文件
	var c mqttAuthACLConfig
	err := json.Unmarshal([]byte(in_str), &c)
	if err != nil {
		LogError(ErrInvalidJsonFormat.Error())
        result.Message = ErrInvalidInputParam.Error()
		return -1
	}

	if err := mqtt_auth_set_cfg_check_param(&c); err != nil {
		LogError(err.Error())
        result.Message = err.Error()
		return -1
	}

	// 解析当前配置文件
	nmc, err := NewNanoMQConfig(NANOMQ_ETC_CONFIG)
	if err != nil {
		LogError("new nanomq config error: %v\n", err)
        result.Message = err.Error()
		return -1
	}
	nmc.Parse()

	// 更新配置缓存
	nmc.AuthLoginList = []AuthLogin{}
	for _, item := range c.LoginAuth {
		nmc.AuthLoginList = append(nmc.AuthLoginList, AuthLogin{
			Login:    item.Username,
			Password: item.Password,
		})
	}
	nmc.ACLRuleList = []ACLRule{}
	for _, item := range c.ACLRule {
		nmc.ACLRuleList = append(nmc.ACLRuleList, ACLRule{
			Permit:   item.Permit,
			Username: item.Username,
			IPAddr:   item.IPAddr,
			ClientID: item.ClientID,
			Action:   item.Action,
			Topics:   item.Topics,
		})
	}
	// 同步配置文件
	err = nmc.Sync()
	if err != nil {
		result.Message = err.Error()
	} else {
		result.Copy(ResultOK)
	}
	return 0
}

//export nanomq_start
func nanomq_start(in_json, out_json *C.char) (ret C.int) {
	var result = httpResult{Code: -1}
	defer func() {
		ret = result.Load(out_json)
	}()

	start_cmd := fmt.Sprintf("nanomq start -d --conf %s --log_file /var/log/nanomq.log", NANOMQ_ETC_CONFIG)
	output, err := exec.Command("/bin/bash", "-c", start_cmd).Output()
	if err != nil {
		LogError("NanoMQ start failed: %v: %s\n", err, string(output))
		result.Message = fmt.Sprintf("NanoMQ start failed: %v", err)
		return -1
	}
	LogDebug("NanoMQ started")

	result.Copy(ResultOK)

	return 0
}

//export nanomq_stop
func nanomq_stop(in_json, out_json *C.char) (ret C.int) {
	var result = httpResult{Code: -1}
	defer func() {
		ret = result.Load(out_json)
	}()

	stop_cmd := "nanomq stop"
	output, err := exec.Command("/bin/bash", "-c", stop_cmd).Output()
	if err != nil {
		LogError("NanoMQ stop failed: %v: %s\n", err, string(output))
		result.Message = fmt.Sprintf("NanoMQ stop failed: %v", err)
		return -1
	}
	LogDebug("NanoMQ stopped")

	result.Copy(ResultOK)

	return 0
}

//export nanomq_restart
func nanomq_restart(in_json, out_json *C.char) C.int {
	nanomq_stop(in_json, out_json)
	return nanomq_start(in_json, out_json)
}

//export nanomq_status
func nanomq_status(in_json, out_json *C.char) (ret C.int) {
	var result = httpResult{Code: -1}
	defer func() {
		ret = result.Load(out_json)
	}()
	// 读取nanomq.pid，获取pid
	pid1, err := os.ReadFile(NANOMQ_PID_FILE)
	if err != nil {
		LogError("NanoMQ is abnormal: read '%s' error: %v\n", NANOMQ_PID_FILE, err)
		result.Message = fmt.Sprintf("NanoMQ is abnormal")
		return -1
	}

	// 执行pidof命令，获取pid
	pid2, err := exec.Command("/bin/bash", "-c", "pidof nanomq").Output()
	if err != nil {
		LogError("NanoMQ is abnormal: exec '%s' error: %v\n", "pidof nanomq", err)
		result.Message = fmt.Sprintf("NanoMQ is abnormal")
		return -1
	}

	// 比较二者是否一致
	if len(pid1) == 0 || len(pid2) == 0 || string(pid1) != string(pid2) {
		LogError("NanoMQ is abnormal: nanomq.pid=%s, pidof(nanomq)=%s\n", string(pid1), string(pid2))
		result.Message = fmt.Sprintf("NanoMQ is abnormal")
		return -1
	}
	LogDebug("NanoMQ is OK")

	result.Copy(ResultOK).Message = "NanoMQ is OK"

	return 0
}

func main() {
}
