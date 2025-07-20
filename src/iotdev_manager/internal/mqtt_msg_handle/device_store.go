package mqtt_msg_handle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	BaseDir = "/var/lib/iot/dev_manager" //iot设备上报信息的存储路径
)

// DeviceStore 设备数据存储接口
type DeviceStore interface {
	// SaveRegistMessage 保存或更新设备注册信息
	SaveRegistMessage(msg *RegistMessage) error

	// SavePressureMessage 保存或更新设备压力数据
	SavePressureMessage(msg *PressureMessage) error

	// SaveMotorMessage 保存或更新设备电机控制指令
	SaveMotorMessage(msg *MotorMessage) error

	// SaveMessage 通用保存消息方法
	SaveMessage(topic string, msg any) error

	// GetDeviceByID 根据设备ID获取设备信息
	GetDeviceByID(deviceID uint16) (any, error)

	// Close 关闭存储，执行清理操作
	Close() error
}

// 全局设备存储实例
var (
	// DefaultDeviceStore 默认设备存储实例
	DefaultDeviceStore DeviceStore

	// 确保存储只初始化一次的锁
	initLock sync.Once

	// 存储初始化错误
	initError error
)

// GetDeviceStore 获取默认设备存储实例
// 如果存储未初始化，会返回错误
func GetDeviceStore() (DeviceStore, error) {

	store, err := newJSONDeviceStore(BaseDir)
	if err != nil {
		initError = fmt.Errorf("failed to initialize device store: %v", err)
		return nil, initError
	}
	DefaultDeviceStore = store

	return DefaultDeviceStore, nil
}

// SaveMessage 使用默认存储保存消息的便捷方法
func SaveMessage(topic string, msg any) error {
	store, err := GetDeviceStore()
	if err != nil {
		return err
	}
	return store.SaveMessage(topic, msg)
}

// FileInfo 文件信息
type FileInfo struct {
	Path          string    // 文件路径
	ModTime       time.Time // 最后修改时间
	LastCheckTime time.Time // 上次检查时间
}

// JSONDeviceStore 基于JSON文件的设备数据存储
type JSONDeviceStore struct {
	baseDir            string         // 存储目录
	registFile         string         // 注册消息文件
	pressureDir        string         // 压力数据目录
	motorDir           string         // 电机控制目录
	mu                 sync.RWMutex   // 内存锁
	devices            map[uint16]any // 设备信息缓存
	registFileChangeTS time.Time      // 注册消息文件修改时间 ,每次加载该文件时，记录该时间，每次处理注册消息时，stat检查文件修改时间和本次记录的时间，如果时间有变化，则重新加载该文件
	// fileInfos     map[string]*FileInfo // 文件信息缓存
	// checkInterval time.Duration        // 文件修改检查间隔
}

// RegistDeviceData 注册设备数据结构
type RegistDeviceData struct {
	DeviceID            uint16      `json:"device_id"`             // 设备标识
	DeviceIP            string      `json:"device_ip"`             // 设备IP地址
	DeviceMaskAddr      string      `json:"device_mask_addr"`      // 设备子网掩码
	DeviceGwAddr        string      `json:"device_gw_addr"`        // 网关地址
	BaudRate            uint32      `json:"baud_rate"`             // 波特率
	WordLength          uint32      `json:"word_length"`           // 数据位
	StopBits            uint32      `json:"stop_bits"`             // 停止位
	Parity              uint32      `json:"parity"`                // 检验位
	Mode                uint32      `json:"mode"`                  // 传输模式
	HwFlowCtl           uint32      `json:"hw_flow_ctl"`           // 流控
	OverSampling        uint32      `json:"over_sampling"`         // 过采样率
	ComProtocol         ComProtocol `json:"com_protocol"`          // 通信协议标准
	MqClientID          string      `json:"mq_client_id"`          // MQTT客户端ID
	MqDeviceName        string      `json:"mq_device_name"`        // MQTT设备ID
	MqDevicePassword    string      `json:"mq_device_password"`    // MQTT设备PIN码
	MqttProtocolVersion uint8       `json:"mqtt_protocol_version"` // MQTT协议版本
	KeepAliveInterval   uint16      `json:"keep_alive_interval"`   // MQTT保活时长
	CleanSession        uint8       `json:"clean_session"`         // 是否启用持久会话
	WillFlag            uint8       `json:"will_flag"`             // 是否启用遗嘱消息
	ServerIP            string      `json:"server_ip"`             // 服务端IP地址
	ServerPort          uint16      `json:"server_port"`           // 服务端端口号
	NetProtocol         uint8       `json:"net_protocol"`          // 传输层协议
	CaCertData          string      `json:"ca_cert_data"`          // ca证书数据 (Base64编码)
	CaCertLen           uint16      `json:"ca_cert_len"`           // ca证书数据长度
	ClientCertData      string      `json:"client_cert_data"`      // 客户端证书数据 (Base64编码)
	ClientCertLen       uint16      `json:"client_cert_len"`       // 客户端证书数据长度
	KeyUpdateTime       uint32      `json:"key_update_time"`       // 密钥更新时间
	AuthType            AuthType    `json:"auth_type"`             // 认证类别
	CollectItem         string      `json:"collect_item"`          // 采集数据项
	CollectTopic        string      `json:"collect_topic"`         // 采集主题
	CollectCycle        uint32      `json:"collect_cycle"`         // 采集周期
	Timestamp           int64       `json:"timestamp"`             // 时间戳
	UpdatedAt           string      `json:"updated_at"`            // 更新时间
}

// PressureDeviceData 压力传感器数据结构
type PressureDeviceData struct {
	DeviceID  uint16 `json:"device_id"`  // 设备标识
	Value     uint32 `json:"value"`      // 压力值
	UpdatedAt string `json:"updated_at"` // 更新时间
}

// MotorDeviceData 电机控制数据结构
type MotorDeviceData struct {
	DeviceID  uint16 `json:"device_id"`  // 设备标识
	Command   uint8  `json:"command"`    // 操作指令
	UpdatedAt string `json:"updated_at"` // 更新时间
}

// newJSONDeviceStore 创建新的JSON设备存储
func newJSONDeviceStore(baseDir string) (*JSONDeviceStore, error) {
	// 创建存储目录
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %v", err)
	}

	pressureDir := filepath.Join(baseDir, "pressure")
	motorDir := filepath.Join(baseDir, "motor")

	// 创建子目录
	if err := os.MkdirAll(pressureDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create pressure directory: %v", err)
	}
	if err := os.MkdirAll(motorDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create motor directory: %v", err)
	}

	store := &JSONDeviceStore{
		baseDir:     baseDir,
		registFile:  filepath.Join(baseDir, "regist.json"),
		pressureDir: pressureDir,
		motorDir:    motorDir,
		devices:     make(map[uint16]any),
	}

	// 加载现有设备数据
	if err := store.loadDevices(); err != nil {
		return nil, err
	}

	return store, nil
}

// SetCheckInterval 设置文件修改检查间隔
// 已废弃，因为不再使用 checkInterval
// func (s *JSONDeviceStore) SetCheckInterval(interval time.Duration) {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()
// 	// s.checkInterval = interval // This line was removed as per the edit hint.
// }

// checkFileModified 检查文件是否被修改
func (s *JSONDeviceStore) checkFileModified(filePath string) (bool, error) {
	// 只处理注册文件
	if filePath != s.registFile {
		return false, nil
	}

	// 获取文件信息
	stat, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false, nil // 文件不存在，不需要重载
	}
	if err != nil {
		return false, fmt.Errorf("failed to stat file %s: %v", filePath, err)
	}

	// 检查修改时间是否变化
	s.mu.RLock()
	lastModTime := s.registFileChangeTS
	s.mu.RUnlock()

	// 如果文件修改时间晚于我们记录的时间，需要重新加载
	if stat.ModTime().After(lastModTime) {
		return true, nil
	}

	return false, nil
}

// loadDevices 加载现有设备数据
func (s *JSONDeviceStore) loadDevices() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 加载注册设备数据
	if _, err := os.Stat(s.registFile); err == nil {
		data, err := os.ReadFile(s.registFile)
		if err != nil {
			return fmt.Errorf("failed to read devices file: %v", err)
		}

		var devices map[string]*RegistDeviceData
		if err := json.Unmarshal(data, &devices); err != nil {
			return fmt.Errorf("failed to parse devices file: %v", err)
		}

		// 将设备数据加载到内存
		for _, device := range devices {
			s.devices[device.DeviceID] = device
		}

		// 更新文件修改时间
		stat, err := os.Stat(s.registFile)
		if err == nil {
			s.registFileChangeTS = stat.ModTime()
		}
	}

	return nil
}

// reloadDeviceIfModified 如果文件被修改，重新加载设备数据
func (s *JSONDeviceStore) reloadDeviceIfModified(deviceID uint16) error {
	// 检查注册设备文件
	modified, err := s.checkFileModified(s.registFile)
	if err != nil {
		return err
	}

	if modified {
		if err := s.loadDevices(); err != nil {
			return err
		}
	}

	// 不检查其它 只有注册信息可能从界面上来删除某条记录

	return nil
}

// SaveRegistMessage 保存或更新设备注册信息
func (s *JSONDeviceStore) SaveRegistMessage(msg *RegistMessage) error {
	// 检查文件是否被修改
	if err := s.reloadDeviceIfModified(msg.DeviceID); err != nil {
		return fmt.Errorf("failed to check file modifications: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 转换为存储格式
	deviceData := &RegistDeviceData{
		DeviceID:            msg.DeviceID,
		DeviceIP:            bytesToString(msg.DeviceIP[:]),
		DeviceMaskAddr:      bytesToString(msg.DeviceMaskAddr[:]),
		DeviceGwAddr:        bytesToString(msg.DeviceGwAddr[:]),
		BaudRate:            msg.BaudRate,
		WordLength:          msg.WordLength,
		StopBits:            msg.StopBits,
		Parity:              msg.Parity,
		Mode:                msg.Mode,
		HwFlowCtl:           msg.HwFlowCtl,
		OverSampling:        msg.OverSampling,
		ComProtocol:         msg.ComProtocol,
		MqClientID:          bytesToString(msg.MqClientID[:]),
		MqDeviceName:        bytesToString(msg.MqDeviceName[:]),
		MqDevicePassword:    bytesToString(msg.MqDevicePassword[:]),
		MqttProtocolVersion: msg.MqttProtocolVersion,
		KeepAliveInterval:   msg.KeepAliveInterval,
		CleanSession:        msg.CleanSession,
		WillFlag:            msg.WillFlag,
		ServerIP:            bytesToString(msg.ServerIP[:]),
		ServerPort:          msg.ServerPort,
		NetProtocol:         msg.NetProtocol,
		CaCertLen:           msg.CaCertLen,
		ClientCertLen:       msg.ClientCertLen,
		KeyUpdateTime:       msg.KeyUpdateTime,
		AuthType:            msg.AuthType,
		CollectItem:         bytesToString(msg.CollectItem[:]),
		CollectTopic:        bytesToString(msg.CollectTopic[:]),
		CollectCycle:        msg.CollectCycle,
		Timestamp:           msg.Timestamp,
		UpdatedAt:           time.Now().Format(time.RFC3339),
	}

	// 如果有证书数据，转换为Base64编码
	if msg.CaCertLen > 0 {
		deviceData.CaCertData = base64.StdEncoding.EncodeToString(msg.CaCertData[:msg.CaCertLen])
	}

	if msg.ClientCertLen > 0 {
		deviceData.ClientCertData = base64.StdEncoding.EncodeToString(msg.ClientCertData[:msg.ClientCertLen])
	}

	// 更新内存中的设备数据
	s.devices[msg.DeviceID] = deviceData

	// 保存所有设备数据到文件
	return s.saveDevicesToFile()
}

// SavePressureMessage 保存或更新设备压力数据
func (s *JSONDeviceStore) SavePressureMessage(msg *PressureMessage) error {

	// 创建压力数据
	pressureData := &PressureDeviceData{
		DeviceID:  msg.DeviceID,
		Value:     msg.Value,
		UpdatedAt: time.Now().Format(time.RFC3339),
	}

	// 设备ID作为文件名
	filename := filepath.Join(s.pressureDir, fmt.Sprintf("%d.json", msg.DeviceID))

	// 保存到独立文件
	if err := s.saveObjectToFile(filename, pressureData); err != nil {
		return err
	}

	// 更新内存缓存
	s.mu.Lock()
	s.devices[msg.DeviceID] = pressureData
	s.mu.Unlock()

	return nil
}

// SaveMotorMessage 保存或更新设备电机控制指令
func (s *JSONDeviceStore) SaveMotorMessage(msg *MotorMessage) error {
	// 检查文件是否被修改
	if err := s.reloadDeviceIfModified(msg.DeviceID); err != nil {
		return fmt.Errorf("failed to check file modifications: %v", err)
	}

	// 创建电机控制数据
	motorData := &MotorDeviceData{
		DeviceID:  msg.DeviceID,
		Command:   msg.Command,
		UpdatedAt: time.Now().Format(time.RFC3339),
	}

	// 设备ID作为文件名
	filename := filepath.Join(s.motorDir, fmt.Sprintf("%d.json", msg.DeviceID))

	// 保存到独立文件
	if err := s.saveObjectToFile(filename, motorData); err != nil {
		return err
	}

	// 更新内存缓存
	s.mu.Lock()
	s.devices[msg.DeviceID] = motorData
	s.mu.Unlock()

	return nil
}

// SaveMessage 通用保存消息方法
func (s *JSONDeviceStore) SaveMessage(topic string, msg any) error {
	switch topic {
	case TopicRegist:
		if registMsg, ok := msg.(*RegistMessage); ok {
			return s.SaveRegistMessage(registMsg)
		}
	case TopicPressure:
		if pressureMsg, ok := msg.(*PressureMessage); ok {
			return s.SavePressureMessage(pressureMsg)
		}
	case TopicMotor:
		if motorMsg, ok := msg.(*MotorMessage); ok {
			return s.SaveMotorMessage(motorMsg)
		}
	}
	return fmt.Errorf("invalid message type for topic %s", topic)
}

// GetDeviceByID 根据设备ID获取设备信息
func (s *JSONDeviceStore) GetDeviceByID(deviceID uint16) (any, error) {
	// 检查文件是否被修改
	if err := s.reloadDeviceIfModified(deviceID); err != nil {
		return nil, fmt.Errorf("failed to check file modifications: %v", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// 查找设备注册信息
	if device, ok := s.devices[deviceID]; ok {
		return device, nil
	}

	// 检查是否有压力数据
	pressureFile := filepath.Join(s.pressureDir, fmt.Sprintf("%d.json", deviceID))
	if _, err := os.Stat(pressureFile); err == nil {
		data, err := os.ReadFile(pressureFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read pressure file: %v", err)
		}

		var pressureData PressureDeviceData
		if err := json.Unmarshal(data, &pressureData); err != nil {
			return nil, fmt.Errorf("failed to parse pressure data: %v", err)
		}

		// 更新内存缓存
		s.mu.RUnlock()
		s.mu.Lock()
		s.devices[deviceID] = &pressureData
		s.mu.Unlock()
		s.mu.RLock()

		return &pressureData, nil
	}

	// 检查是否有电机控制数据
	motorFile := filepath.Join(s.motorDir, fmt.Sprintf("%d.json", deviceID))
	if _, err := os.Stat(motorFile); err == nil {
		data, err := os.ReadFile(motorFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read motor file: %v", err)
		}

		var motorData MotorDeviceData
		if err := json.Unmarshal(data, &motorData); err != nil {
			return nil, fmt.Errorf("failed to parse motor data: %v", err)
		}

		// 更新内存缓存
		s.mu.RUnlock()
		s.mu.Lock()
		s.devices[deviceID] = &motorData
		s.mu.Unlock()
		s.mu.RLock()

		return &motorData, nil
	}

	return nil, fmt.Errorf("device with ID %d not found", deviceID)
}

// Close 关闭存储，执行清理操作
func (s *JSONDeviceStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 保存所有设备数据
	return s.saveDevicesToFile()
}

// saveDevicesToFile 保存所有设备数据到文件
func (s *JSONDeviceStore) saveDevicesToFile() error {
	// 提取注册设备数据
	devices := make(map[string]*RegistDeviceData)
	for id, device := range s.devices {
		if regDevice, ok := device.(*RegistDeviceData); ok {
			devices[strconv.Itoa(int(id))] = regDevice
		}
	}

	// 序列化为JSON
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize devices: %v", err)
	}

	// 使用文件锁保存
	if err := s.saveDataToFile(s.registFile, data); err != nil {
		return err
	}

	// 更新文件修改时间
	stat, err := os.Stat(s.registFile)
	if err != nil {
		return fmt.Errorf("failed to stat file after save: %v", err)
	}

	// 更新文件修改时间
	s.registFileChangeTS = stat.ModTime()

	return nil
}

// saveObjectToFile 将对象保存到JSON文件
func (s *JSONDeviceStore) saveObjectToFile(filename string, obj any) error {
	// 序列化为JSON
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize object: %v", err)
	}

	// 使用文件锁保存
	if err := s.saveDataToFile(filename, data); err != nil {
		return err
	}

	// 如果是注册文件，更新修改时间
	if filename == s.registFile {
		stat, err := os.Stat(filename)
		if err != nil {
			return fmt.Errorf("failed to stat file after save: %v", err)
		}

		s.mu.Lock()
		s.registFileChangeTS = stat.ModTime()
		s.mu.Unlock()
	}

	return nil
}

// saveDataToFile 使用文件锁保存数据到文件
func (s *JSONDeviceStore) saveDataToFile(filename string, data []byte) error {
	// 确保目录存在
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// 打开文件并加锁
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// 应用独占写入锁
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to lock file: %v", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	// 写入数据
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %v", err)
	}

	return nil
}
