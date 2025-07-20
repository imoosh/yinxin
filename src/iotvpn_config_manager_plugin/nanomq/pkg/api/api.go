package api

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
	"fmt"
	. "iotvpn_config_manager_plugin/nanomq/pkg/conf"
	. "iotvpn_config_manager_plugin/nanomq/pkg/log"
	"iotvpn_config_manager_plugin/nanomq/pkg/types"
	"os"
	"os/exec"
)


func GetNanoMQConfig(input string) (result *types.BaseResponse, err error) {
	result = types.NewBaseResponseBAD()

	nmc, err := NewNanoMQConfig(types.NANOMQ_ETC_CONFIG)
	if err != nil {
		LogError(err.Error())
		result.Message = types.ErrLoadNanoMQConfigFailed.Error()
		return
	}
	nmc.Parse()

	var c types.NanoMQServiceConfig
	c.ListenersSSL.Port = nmc.TLSPort
	c.ListenersSSL.VerifyPeer = nmc.TLSVerifyPeer
	c.HttpServer.Port = nmc.HTTPServerPort
	c.Log.Level = nmc.LogLevel

	result = types.NewBaseResponseOK()
	result.Result = &c

	return
}

func checkNanoMQSetConfig(conf *types.NanoMQServiceConfig) error {
	if conf.HttpServer.Port <= 0 || conf.HttpServer.Port >= 65536 {
		return fmt.Errorf("Invalid nanomq service paramater: nanomq http server port must be [0,65535]")
	}
	if conf.ListenersSSL.Port <= 0 || conf.ListenersSSL.Port >= 65536 {
		return fmt.Errorf("Invalid nanomq service paramater: nanomq ssl port must be [0,65535]")
	}
	if _, ok := types.NanoMQLogLevel[conf.Log.Level]; !ok {
		return fmt.Errorf("Invalid nanomq service paramater: nanomq log level must be [trace, debug, info, warn, error, fatal]")
	}

	return nil
}

func SetNanoMQConfig(input string) (result *types.BaseResponse, err error) {
	result = types.NewBaseResponseBAD()

	if input == "" {
		LogError(types.ErrInvalidInputParam.Error())
		result.Message = types.ErrInvalidInputParam.Error()
		return
	}

	LogDebug("in_json: %s\n", input)

	// 解析当前配置文件
	var c types.NanoMQServiceConfig
	if err = json.Unmarshal([]byte(input), &c); err != nil {
		LogError(types.ErrInvalidJsonFormat.Error())
		result.Message = types.ErrInvalidJsonFormat.Error()
		return
	}

	if err = checkNanoMQSetConfig(&c); err != nil {
		LogError(err.Error())
		result.Message = err.Error()
		return
	}

	nmc, err := NewNanoMQConfig(types.NANOMQ_ETC_CONFIG)
	if err != nil {
		LogError("new nanomq config error: %v\n", err)
		result.Message = types.ErrLoadNanoMQConfigFailed.Error()
		return
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
		result = types.NewBaseResponseOK()
	}
	return
}

func GetMQTTAuthConfig(input string) (result *types.BaseResponse, err error) {
	result = types.NewBaseResponseBAD()

	nmc, err := NewNanoMQConfig(types.NANOMQ_ETC_CONFIG)
	if err != nil {
		LogError("new nanomq config error: %v\n", err)
		result.Message = types.ErrLoadNanoMQConfigFailed.Error()
		return
	}
	nmc.Parse()

	var c types.MQTTAuthACLConfig
	for id, item := range nmc.AuthLoginList {
		c.LoginAuth = append(c.LoginAuth, types.MQTTLoginAuth{
			Id:       id + 1,
			Username: item.Login,
			Password: item.Password,
		})
	}
	for id, item := range nmc.ACLConf.ACLRuleList {
		c.ACLRule = append(c.ACLRule, types.MQTTACLRule{
			Id:       id + 1,
			Permit:   item.Permit,
			Username: item.Username,
			Action:   item.Action,
			Topics:   item.Topics,
		})
	}

	result = types.NewBaseResponseOK()
	result.Result = &c

	return
}

func checkMQTTAuthSetConfig(conf *types.MQTTAuthACLConfig) error {
	for idx, item := range conf.LoginAuth {
		fmt.Printf("login_auth ==> idx=%d, id=%d\n", idx+1, item.Id)
		if item.Id != idx+1 {
			return fmt.Errorf("Invalid login auth paramater: id is wrong")
		}
		if item.Username == "" || item.Password == "" {
			return fmt.Errorf("Invalid login auth paramater: username or password is empty")
		}
	}

	for idx, item := range conf.ACLRule {
		fmt.Printf("acl_rule   ==> idx=%d, id=%d\n", idx+1, item.Id)
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

func SetMQTTAuthConfig(input string) (result *types.BaseResponse, err error) {
	result = types.NewBaseResponseBAD()

	if input == "" {
		LogError(types.ErrInvalidInputParam.Error())
		result.Message = types.ErrInvalidInputParam.Error()
		return
	}

	LogDebug("input: %s\n", input)

	// 解析当前配置文件
	var c types.MQTTAuthACLConfig
	err = json.Unmarshal([]byte(input), &c)
	if err != nil {
		LogError(types.ErrInvalidJsonFormat.Error())
		result.Message = types.ErrInvalidJsonFormat.Error()
		return
	}

	if err = checkMQTTAuthSetConfig(&c); err != nil {
		LogError(err.Error())
		result.Message = err.Error()
		return
	}

	// 解析当前配置文件
	nmc, err := NewNanoMQConfig(types.NANOMQ_ETC_CONFIG)
	if err != nil {
		LogError("new nanomq config error: %v\n", err)
		result.Message = err.Error()
		return
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
		result = types.NewBaseResponseOK()
	}
	return
}

func StartNanoMQService(input string) (result *types.BaseResponse, err error) {
	result = types.NewBaseResponseBAD()

	start_cmd := fmt.Sprintf("nanomq start --old_conf %s", types.NANOMQ_ETC_CONFIG)
	output, err := exec.Command("/bin/bash", "-c", start_cmd).Output()
	if err != nil {
		LogError("NanoMQ start failed: %v: %s\n", err, string(output))
		result.Message = fmt.Sprintf("NanoMQ start failed: %v", err)
		return
	}
	LogDebug("NanoMQ started")

	result = types.NewBaseResponseOK()

	return
}

func StopNanoMQService(input string) (result *types.BaseResponse, err error) {
	result = types.NewBaseResponseBAD()

	stop_cmd := "nanomq stop"
	output, err := exec.Command("/bin/bash", "-c", stop_cmd).Output()
	if err != nil {
		LogError("NanoMQ stop failed: %v: %s\n", err, string(output))
		result.Message = fmt.Sprintf("NanoMQ stop failed: %v", err)
		return
	}
	LogDebug("NanoMQ stopped")

	result = types.NewBaseResponseOK()

	return
}

func RestartNanoMQService(input string) (*types.BaseResponse, error) {
	StopNanoMQService(input)
	return StartNanoMQService(input)
}

func GetNanoMQStatus(input string) (result *types.BaseResponse, err error) {
	result = types.NewBaseResponseBAD()

	// 读取nanomq.pid，获取pid
	pid1, err := os.ReadFile(types.NANOMQ_PID_FILE)
	if err != nil {
		LogError("NanoMQ is abnormal: read '%s' error: %v\n", types.NANOMQ_PID_FILE, err)
		result.Message = fmt.Sprintf("NanoMQ is abnormal")
		return
	}

	// 执行pidof命令，获取pid
	pid2, err := exec.Command("/bin/bash", "-c", "pidof nanomq").Output()
	if err != nil {
		LogError("NanoMQ is abnormal: exec '%s' error: %v\n", "pidof nanomq", err)
		result.Message = fmt.Sprintf("NanoMQ is abnormal")
		return
	}

	// 比较二者是否一致
	if len(pid1) == 0 || len(pid2) == 0 || string(pid1) != string(pid2) {
		LogError("NanoMQ is abnormal: nanomq.pid=%s, pidof(nanomq)=%s\n", string(pid1), string(pid2))
		result.Message = fmt.Sprintf("NanoMQ is abnormal")
		return
	}
	LogDebug("NanoMQ is OK")

	result = types.NewBaseResponseOK()

	return
}
