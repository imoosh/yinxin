package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 应用程序配置结构
type Config struct {
	App  AppConfig  `yaml:"app"`
	Log  LogConfig  `yaml:"log"`
	MQTT MQTTConfig `yaml:"mqtt"`
}

// AppConfig 应用程序基本配置
type AppConfig struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	Port    int    `yaml:"port"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level   string `yaml:"level"`
	File    string `yaml:"file"`
	Console bool   `yaml:"console"`
}

type MQTTConfig struct {
	Broker string `yaml:"broker"`
	TLS    struct {
		Enabled    bool   `yaml:"enabled"`
		CaCert     string `yaml:"caCert"`
		ClientCert string `yaml:"clientCert"`
		ClientKey  string `yaml:"clientKey"`
	} `yaml:"tls"`
	Topic                string `yaml:"topic"`
	ClientID             string `yaml:"clientID"`
	Username             string `yaml:"username"`
	Password             string `yaml:"password"`
	QoS                  byte   `yaml:"qos"`
	KeepAlive            int    `yaml:"keepAlive"`
	ReconnectInterval    int    `yaml:"reconnectInterval"`
	MaxReconnectAttempts int    `yaml:"maxReconnectAttempts"`
}

// LoadConfig 从指定路径加载配置文件
func LoadConfig(configPath string) (*Config, error) {
	// 获取绝对路径
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// 读取配置文件
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// 解析YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// PrintConfig 逐行打印配置项
func (c *Config) Print(output func(string, ...interface{})) {
	output("=============== 配置信息 ===============")
	printStruct(reflect.ValueOf(c).Elem(), "", output)
	output("========================================")
}

// printStruct 递归打印结构体字段
func printStruct(v reflect.Value, prefix string, output func(string, ...interface{})) {
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// 获取yaml标签名称
		tagName := fieldType.Tag.Get("yaml")
		if tagName == "" {
			tagName = strings.ToLower(fieldType.Name)
		} else {
			// 处理yaml标签中可能包含的逗号
			tagName = strings.Split(tagName, ",")[0]
		}

		// 构建完整的键名
		key := prefix
		if prefix != "" {
			key += "."
		}
		key += tagName

		// 根据字段类型进行处理
		switch field.Kind() {
		case reflect.Struct:
			// 递归处理嵌套结构体
			printStruct(field, key, output)
		case reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64, reflect.Bool:
			// 处理敏感信息（如密码）
			value := field.Interface()
			if strings.Contains(strings.ToLower(key), "password") {
				output("%s: ******", key)
			} else {
				output("%s: %v", key, value)
			}
		case reflect.Slice, reflect.Array:
			// 处理数组和切片
			output("%s: (长度: %d)", key, field.Len())
			for j := 0; j < field.Len(); j++ {
				element := field.Index(j)
				if element.Kind() == reflect.Struct {
					printStruct(element, fmt.Sprintf("%s[%d]", key, j), output)
				} else {
					output("%s[%d]: %v", key, j, element.Interface())
				}
			}
		case reflect.Map:
			// 处理映射
			output("%s: (键值对: %d)", key, field.Len())
			for _, k := range field.MapKeys() {
				v := field.MapIndex(k)
				output("%s[%v]: %v", key, k.Interface(), v.Interface())
			}
		case reflect.Ptr:
			// 处理指针
			if !field.IsNil() {
				printStruct(field.Elem(), key, output)
			} else {
				output("%s: <nil>", key)
			}
		default:
			output("%s: %v (未知类型)", key, field.Interface())
		}
	}
}
