package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"iotvpn_config_manager_plugin/iotdev_manager_plugin/pkg/types"
)

const (
	// 设备管理数据存储路径
	deviceStorePath = "/var/lib/iot/dev_manager"
	// 注册设备数据文件
	registFile = "regist.json"
)

// 错误码定义
const (
	ErrOk           = 0
	ErrInvalidParam = -1
	ErrInternal     = -2
	ErrNotFound     = -3
)

// 错误描述
func getErrDesc(code int, customMsg string) string {
	var baseMsg string
	switch code {
	case ErrOk:
		baseMsg = "success"
	case ErrInvalidParam:
		baseMsg = "invalid parameter"
	case ErrInternal:
		baseMsg = "internal error"
	case ErrNotFound:
		baseMsg = "not found"
	default:
		baseMsg = "unknown error"
	}

	if customMsg != "" {
		return fmt.Sprintf("code:%d ,msg:%s ,%s", code, baseMsg, customMsg)
	}
	return fmt.Sprintf("code:%d ,msg:%s", code, baseMsg)
}

// 创建错误响应
func newErrorResponse(code int, customMsg string) *types.BaseResponse {
	return &types.BaseResponse{
		Code: code,
		Msg:  getErrDesc(code, customMsg),
		Data: map[string]interface{}{},
	}
}

// GetIot 获取所有IOT设备信息
func GetIot(inputStr string) (*types.BaseResponse, error) {
	// 读取设备注册文件
	registFilePath := filepath.Join(deviceStorePath, registFile)

	// 检查文件是否存在
	if _, err := os.Stat(registFilePath); os.IsNotExist(err) {
		// 文件不存在，返回空列表
		return &types.BaseResponse{
			Code: ErrOk,
			Msg:  getErrDesc(ErrOk, ""),
			Data: map[string]interface{}{
				"iot": []interface{}{},
			},
		}, nil
	}

	// 读取文件内容
	data, err := os.ReadFile(registFilePath)
	if err != nil {
		return newErrorResponse(ErrInternal, fmt.Sprintf("failed to read device data: %v", err)), nil
	}

	// 解析JSON数据
	var devices map[string]map[string]interface{}
	if err := json.Unmarshal(data, &devices); err != nil {
		return newErrorResponse(ErrInternal, fmt.Sprintf("failed to parse device data: %v", err)), nil
	}

	// 转换为响应格式
	var iotDevices []map[string]interface{}
	for devID, device := range devices {
		// 提取设备信息
		deviceInfo := map[string]interface{}{
			"devid": devID,
			"name":  fmt.Sprintf("设备-%s", devID),
		}

		// 从设备数据中提取IP地址
		if deviceIP, ok := device["device_ip"]; ok {
			deviceInfo["ip"] = deviceIP
		} else {
			deviceInfo["ip"] = ""
		}

		// 添加网络和压力信息（模拟数据，根据实际需求可从其他文件读取）
		deviceInfo["pressure"] = 1
		deviceInfo["net_rx"] = 999
		deviceInfo["net_tx"] = 666
		deviceInfo["net_packet_loss_rate"] = 20

		iotDevices = append(iotDevices, deviceInfo)
	}

	return &types.BaseResponse{
		Code: ErrOk,
		Msg:  getErrDesc(ErrOk, ""),
		Data: map[string]interface{}{
			"iot": iotDevices,
		},
	}, nil
}

// DeleteIot 删除指定IOT设备
func DeleteIot(inputStr string) (*types.BaseResponse, error) {
	// 解析输入参数
	var input struct {
		DevID string `json:"devid"`
	}

	if err := json.Unmarshal([]byte(inputStr), &input); err != nil {
		return newErrorResponse(ErrInvalidParam, fmt.Sprintf("invalid input format: %v", err)), nil
	}

	// 检查设备ID是否为空
	if input.DevID == "" {
		return newErrorResponse(ErrInvalidParam, "device id is required"), nil
	}

	// 读取设备注册文件
	registFilePath := filepath.Join(deviceStorePath, registFile)

	// 检查文件是否存在
	if _, err := os.Stat(registFilePath); os.IsNotExist(err) {
		return newErrorResponse(ErrNotFound, "device data file not found"), nil
	}

	// 读取文件内容
	data, err := os.ReadFile(registFilePath)
	if err != nil {
		return newErrorResponse(ErrInternal, fmt.Sprintf("failed to read device data: %v", err)), nil
	}

	// 解析JSON数据
	var devices map[string]map[string]interface{}
	if err := json.Unmarshal(data, &devices); err != nil {
		return newErrorResponse(ErrInternal, fmt.Sprintf("failed to parse device data: %v", err)), nil
	}

	// 检查设备是否存在
	if _, exists := devices[input.DevID]; !exists {
		return newErrorResponse(ErrNotFound, fmt.Sprintf("device with id %s not found", input.DevID)), nil
	}

	// 删除设备
	delete(devices, input.DevID)

	// 保存更新后的数据
	updatedData, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return newErrorResponse(ErrInternal, fmt.Sprintf("failed to serialize device data: %v", err)), nil
	}

	// 写入文件
	if err := os.WriteFile(registFilePath, updatedData, 0644); err != nil {
		return newErrorResponse(ErrInternal, fmt.Sprintf("failed to save device data: %v", err)), nil
	}

	// 删除设备对应的压力和电机数据文件（如果存在）
	deviceID, _ := strconv.ParseUint(input.DevID, 10, 16)
	pressureFile := filepath.Join(deviceStorePath, "pressure", fmt.Sprintf("%d.json", deviceID))
	motorFile := filepath.Join(deviceStorePath, "motor", fmt.Sprintf("%d.json", deviceID))

	// 尝试删除压力数据文件（忽略错误）
	os.Remove(pressureFile)

	// 尝试删除电机数据文件（忽略错误）
	os.Remove(motorFile)

	return &types.BaseResponse{
		Code: ErrOk,
		Msg:  getErrDesc(ErrOk, "device deleted successfully"),
		Data: map[string]interface{}{},
	}, nil
}
