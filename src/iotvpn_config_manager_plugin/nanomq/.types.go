package main

import (
	// "time"
    "errors"
)

var (
    ErrInvalidInputParam = errors.New("invalid input param")
    ErrInvalidJsonFormat = errors.New("invalid json format")
)

// NanomqConfig 表示整个配置结构
type NanomqConfig struct {
	MQTT         MQTTConfig         `json:"mqtt"`
	ListenersTCP ListenersTCPConfig `json:"listeners.tcp"`
	ListenersSSL ListenersSSLConfig `json:"listeners.ssl"`
	ListenersWS  ListenersWSConfig  `json:"listeners.ws"`
	HTTPServer   HTTPServerConfig   `json:"http_server"`
	Log          LogConfig          `json:"log"`
}

// MQTTConfig 表示MQTT相关配置
type MQTTConfig struct {
	PropertySize  int           `json:"property_size"`
	MaxPacketSize string        `json:"max_packet_size"`
	MaxMQueueLen  int           `json:"max_mqueue_len"`
	//RetryInterval time.Duration `json:"retry_interval"`
}

// ListenersTCPConfig 表示MQTT/TCP监听器配置
type ListenersTCPConfig struct {
	Bind string `json:"bind"`
}

// ListenersSSLConfig 表示MQTT/SSL监听器配置
type ListenersSSLConfig struct {
	Bind       string `json:"bind"`
	VerifyPeer bool   `json:"verify_peer"`
}

// ListenersWSConfig 表示MQTT/WebSocket监听器配置
type ListenersWSConfig struct {
	Bind string `json:"bind"`
}

// HTTPServerConfig 表示HTTP服务器配置
type HTTPServerConfig struct {
	Port int `json:"port"`
}

// LogConfig 表示日志配置
type LogConfig struct {
	Level string `json:"level"`
}
