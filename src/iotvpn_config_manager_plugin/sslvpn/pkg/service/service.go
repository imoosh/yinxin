package service

import (
	"fmt"
	"iotvpn_config_manager_plugin/sslvpn/pkg/defines"
	"os"
	"os/exec"
	"strings"
	"time"
)

//openvpn 服务管理

// ServiceManager 服务管理器
type ServiceManager struct {
	ServiceName     string
	ConfigPath      string
	DefaultConfPath string
}

// NewServiceManager 创建服务管理器
func NewServiceManager() *ServiceManager {
	return &ServiceManager{
		ServiceName:     "openvpn",
		ConfigPath:      defines.OpenVPNMainPath,
		DefaultConfPath: defines.OpenVPNMainPath + ".default",
	}
}

// CheckStatus 检查服务状态
func (sm *ServiceManager) CheckStatus() (bool, bool, bool, error) {
	// 检查配置文件是否存在
	cfgOk := false

	//运行服务必须要有主配置文件和 证书、密钥、ca
	if _, err := os.Stat(sm.ConfigPath); err == nil {
		if _, err := os.Stat(defines.CommonCACertPath); err == nil {
			if _, err := os.Stat(defines.CommonServerCertPath); err == nil {
				if _, err := os.Stat(defines.CommonServerKeyPath); err == nil {
					cfgOk = true
				}
			}
		}
	}

	// 检查配置文件是否为默认配置
	cfgIsDefault := false
	if cfgOk { //TODO 修改检查逻辑 默认配置文件是固定的 应根据字符串比较来确定
		cfgIsDefault = false //TODO
	} else {
		cfgIsDefault = true
	}

	// 检查服务运行状态
	serviceStatus := false
	cmd := exec.Command("systemctl", "is-active", sm.ServiceName)
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		serviceStatus = true
	}

	return cfgIsDefault, cfgOk, serviceStatus, nil
}

// RestartService 重启服务
func (sm *ServiceManager) RestartService(cidrNet string) error {
	// 检查配置文件是否存在
	if _, err := os.Stat(sm.ConfigPath); err != nil {
		return fmt.Errorf("config file not found: %s", sm.ConfigPath)
	}

	// 重启服务
	cmd := exec.Command("systemctl", "restart", sm.ServiceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart service: %v", err)
	}

	// 等待服务启动
	time.Sleep(2 * time.Second)

	// 验证服务是否成功启动
	cmd = exec.Command("systemctl", "is-active", sm.ServiceName)
	output, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(output)) != "active" {
		return fmt.Errorf("service failed to start properly")
	}

	return nil
}

// StopService 停止服务
func (sm *ServiceManager) StopService() error {
	cmd := exec.Command("systemctl", "stop", sm.ServiceName)
	return cmd.Run()
}

// StartService 启动服务
func (sm *ServiceManager) StartService() error {
	cmd := exec.Command("systemctl", "start", sm.ServiceName)
	return cmd.Run()
}
