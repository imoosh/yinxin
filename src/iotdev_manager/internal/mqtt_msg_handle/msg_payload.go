package mqtt_msg_handle

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Topic constants
const (
	TopicRegist   = "regist"   // 设备注册主题
	TopicPressure = "pressure" // 压力传感器主题
	TopicMotor    = "motor"    // 电机控制主题
)

// ComProtocol 通信协议标准
type ComProtocol uint32

const (
	COM_RS232 ComProtocol = 0
	COM_RS485 ComProtocol = 1
)

// AuthType 认证类别
type AuthType uint32

const (
	AUTH_TYPE_CERT AuthType = 0
)

// RegistMessage 注册消息结构体
type RegistMessage struct {
	DeviceID            uint16      `json:"device_id"`             // 设备标识
	DeviceIP            [32]byte    `json:"device_ip"`             // 设备IP地址
	DeviceMaskAddr      [32]byte    `json:"device_mask_addr"`      // 设备子网掩码
	DeviceGwAddr        [32]byte    `json:"device_gw_addr"`        // 网关地址
	BaudRate            uint32      `json:"baud_rate"`             // 波特率
	WordLength          uint32      `json:"word_length"`           // 数据位
	StopBits            uint32      `json:"stop_bits"`             // 停止位
	Parity              uint32      `json:"parity"`                // 检验位
	Mode                uint32      `json:"mode"`                  // 传输模式
	HwFlowCtl           uint32      `json:"hw_flow_ctl"`           // 流控
	OverSampling        uint32      `json:"over_sampling"`         // 过采样率
	ComProtocol         ComProtocol `json:"com_protocol"`          // 通信协议标准
	MqClientID          [16]byte    `json:"mq_client_id"`          // MQTT客户端ID
	MqDeviceName        [16]byte    `json:"mq_device_name"`        // MQTT设备ID
	MqDevicePassword    [8]byte     `json:"mq_device_password"`    // MQTT设备PIN码
	MqttProtocolVersion uint8       `json:"mqtt_protocol_version"` // MQTT协议版本
	KeepAliveInterval   uint16      `json:"keep_alive_interval"`   // MQTT保活时长
	CleanSession        uint8       `json:"clean_session"`         // 是否启用持久会话
	WillFlag            uint8       `json:"will_flag"`             // 是否启用遗嘱消息
	ServerIP            [32]byte    `json:"server_ip"`             // 服务端IP地址
	ServerPort          uint16      `json:"server_port"`           // 服务端端口号
	NetProtocol         uint8       `json:"net_protocol"`          // 传输层协议
	CaCertData          [1024]byte  `json:"ca_cert_data"`          // ca证书数据
	CaCertLen           uint16      `json:"ca_cert_len"`           // ca证书数据长度
	ClientCertData      [1024]byte  `json:"client_cert_data"`      // 客户端证书数据
	ClientCertLen       uint16      `json:"client_cert_len"`       // 客户端证书数据长度
	KeyUpdateTime       uint32      `json:"key_update_time"`       // 密钥更新时间
	AuthType            AuthType    `json:"auth_type"`             // 认证类别
	CollectItem         [32]byte    `json:"collect_item"`          // 采集数据项
	CollectTopic        [32]byte    `json:"collect_topic"`         // 采集主题
	CollectCycle        uint32      `json:"collect_cycle"`         // 采集周期
	Timestamp           int64       `json:"timestamp"`             // 时间戳
}

// PressureMessage 压力传感器数值消息结构体
type PressureMessage struct {
	Value    uint32 `json:"value"`     // 压力值
	DeviceID uint16 `json:"device_id"` // 设备标识
}

// MotorMessage 电机操作指令消息结构体
type MotorMessage struct {
	Command  uint8  `json:"command"`   // 操作指令 (0-停止, 1-正转, 2-反转)
	DeviceID uint16 `json:"device_id"` // 设备标识
}

// ParseRegistMessage 解析注册消息从网络字节序buffer
func ParseRegistMessage(data []byte) (*RegistMessage, error) {
	if len(data) < binary.Size(&RegistMessage{}) {
		return nil, fmt.Errorf("data too short for RegistMessage")
	}

	msg := &RegistMessage{}
	reader := bytes.NewReader(data)

	// 按网络字节序（大端序）解析
	if err := binary.Read(reader, binary.BigEndian, msg); err != nil {
		return nil, fmt.Errorf("failed to parse RegistMessage: %v", err)
	}

	return msg, nil
}

// ParsePressureMessage 解析压力传感器消息从网络字节序buffer
func ParsePressureMessage(data []byte) (*PressureMessage, error) {
	if len(data) < binary.Size(&PressureMessage{}) {
		return nil, fmt.Errorf("data too short for PressureMessage")
	}

	msg := &PressureMessage{}
	reader := bytes.NewReader(data)

	// 按网络字节序（大端序）解析
	if err := binary.Read(reader, binary.BigEndian, msg); err != nil {
		return nil, fmt.Errorf("failed to parse PressureMessage: %v", err)
	}

	return msg, nil
}

// ParseMotorMessage 解析电机操作指令消息从网络字节序buffer
func ParseMotorMessage(data []byte) (*MotorMessage, error) {
	if len(data) < binary.Size(&MotorMessage{}) {
		return nil, fmt.Errorf("data too short for MotorMessage")
	}

	msg := &MotorMessage{}
	reader := bytes.NewReader(data)

	// 按网络字节序（大端序）解析
	if err := binary.Read(reader, binary.BigEndian, msg); err != nil {
		return nil, fmt.Errorf("failed to parse MotorMessage: %v", err)
	}

	return msg, nil
}

// bytesToString 将字节数组转换为字符串，去除空字符
func bytesToString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

// ParseMessage 根据主题解析消息
func ParseMessage(topic string, data []byte) (any, error) {
	switch topic {
	case TopicRegist:
		return ParseRegistMessage(data)
	case TopicPressure:
		return ParsePressureMessage(data)
	case TopicMotor:
		return ParseMotorMessage(data)
	default:
		return nil, fmt.Errorf("unknown topic: %s", topic)
	}
}
