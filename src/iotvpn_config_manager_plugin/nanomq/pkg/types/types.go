package types

import (
	"errors"
)

type BaseResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Result  interface{} `json:"result"`
}

func NewBaseResponse() *BaseResponse {
	return &BaseResponse{
		Code:    0,
		Message: "",
		Result:  struct{}{},
	}
}

func NewBaseResponseBAD() *BaseResponse {
	return &BaseResponse{
		Code:    -1,
		Message: "failure",
		Result:  struct{}{},
	}
}

func NewBaseResponseOK() *BaseResponse {
	return &BaseResponse{
		Code:    0,
		Message: "success",
		Result:  struct{}{},
	}
}

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

	NanoMQLogLevel = map[string]interface{}{
		"trace": nil,
		"debug": nil,
		"info":  nil,
		"warn":  nil,
		"error": nil,
		"fatal": nil,
	}
)

type NanomqListenersSSL struct {
	Port       int  `json:"port"`
	VerifyPeer bool `json:"verify_peer"`
}

type NanomqHttpServer struct {
	Port int `json:"port"`
}

type NanomqLog struct {
	Level string `json:"level"`
}

type NanoMQServiceConfig struct {
	ListenersSSL NanomqListenersSSL `json:"listeners.ssl"`
	HttpServer   NanomqHttpServer   `json:"http_server"`
	Log          NanomqLog          `json:"log"`
}

type MQTTLoginAuth struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type MQTTACLRule struct {
	Id     int    `json:"id"`
	Permit string `json:"permit,omitempty"`
	// ipaddr,clientid,username 三选一
	Username string `json:"username,omitempty"`
	IPAddr   string `json:"ipaddr,omitempty"`
	ClientID string `json:"clientid,omitempty"`

	Action string   `json:"action,omitempty"`
	Topics []string `json:"topics,omitempty"`
}

type MQTTAuthACLConfig struct {
	LoginAuth []MQTTLoginAuth `json:"login_auth"`
	ACLRule   []MQTTACLRule   `json:"acl_rule"`
}
