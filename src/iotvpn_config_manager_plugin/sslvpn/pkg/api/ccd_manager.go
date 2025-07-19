package api

import (
	"fmt"
	"iotvpn_config_manager_plugin/sslvpn/pkg/alg"
	"iotvpn_config_manager_plugin/sslvpn/pkg/defines"
	"iotvpn_config_manager_plugin/sslvpn/pkg/types"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CCDManager OpenVPN客户端配置目录管理器
type CCDManager struct {
	ccdDir string
}

// NewCCDManager 创建CCD管理器
func NewCCDManager() *CCDManager {
	return &CCDManager{
		ccdDir: defines.OpenVPNCCDDir,
	}
}

// UpdateConfigs 更新CCD配置
func (cm *CCDManager) UpdateConfigs(oldUsers, newUsers []types.User) error {
	// 使用CompareSlice对比用户变化
	keyFunc := func(user types.User) string {
		return user.UUID // 使用UUID作为唯一标识
	}

	compareFunc := func(left, right types.User) bool {
		// 比较影响CCD配置的关键字段
		return left.CertCN == right.CertCN &&
			left.BindIP == right.BindIP &&
			left.Enable == right.Enable
	}

	same, deleted, added, modified := alg.CompareSlice(oldUsers, newUsers, keyFunc, compareFunc)

	// 处理删除的用户：删除其CCD配置文件
	for _, user := range deleted {
		if err := cm.deleteCCDConfig(user); err != nil {
			fmt.Printf("Warning: failed to delete CCD config for user %s (%s): %v\n",
				user.Name, user.CertCN, err)
		}
	}

	// 处理新增的用户：创建CCD配置文件
	for _, user := range added {
		if user.Enable && user.CertCN != "" {
			if err := cm.createCCDConfig(user); err != nil {
				fmt.Printf("Warning: failed to create CCD config for user %s (%s): %v\n",
					user.Name, user.CertCN, err)
			}
		}
	}

	// 处理修改的用户：更新CCD配置文件
	for _, user := range modified {
		// 先删除旧配置（如果存在）
		if oldUser := findUserByUUID(oldUsers, user.UUID); oldUser != nil && oldUser.CertCN != "" {
			if err := cm.deleteCCDConfig(*oldUser); err != nil {
				fmt.Printf("Warning: failed to delete old CCD config for user %s: %v\n",
					oldUser.Name, err)
			}
		}

		// 创建新配置（如果用户启用且有CN）
		if user.Enable && user.CertCN != "" {
			if err := cm.createCCDConfig(user); err != nil {
				fmt.Printf("Warning: failed to create updated CCD config for user %s (%s): %v\n",
					user.Name, user.CertCN, err)
			}
		}
	}

	// 对于相同的用户，不需要做任何操作
	_ = same

	return nil
}

// createCCDConfig 创建用户的CCD配置文件
func (cm *CCDManager) createCCDConfig(user types.User) error {
	if user.CertCN == "" {
		return fmt.Errorf("user %s has empty certificate CN", user.Name)
	}

	// 确保CCD目录存在
	if err := os.MkdirAll(cm.ccdDir, 0755); err != nil {
		return fmt.Errorf("failed to create CCD directory: %v", err)
	}

	// CCD文件路径，以证书CN命名
	ccdFile := filepath.Join(cm.ccdDir, user.CertCN)

	// 生成CCD配置内容
	var config strings.Builder

	// 添加注释
	config.WriteString(fmt.Sprintf("# CCD Configuration for user: %s (UUID: %s)\n",
		user.Name, user.UUID))
	config.WriteString(fmt.Sprintf("# Generated at: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// 分配固定IP地址 - 使用subnet拓扑语法
	if user.BindIP != "" {
		// 获取服务器网段配置来确定子网掩码
		serverNetMask, err := cm.getServerNetMask()
		if err != nil {
			fmt.Printf("Warning: failed to get server net mask, using default 255.255.255.0: %v\n", err)
			serverNetMask = "255.255.255.0"
		}

		config.WriteString(fmt.Sprintf("# 为客户端分配固定IP地址 (subnet拓扑)\n"))
		config.WriteString(fmt.Sprintf("ifconfig-push %s %s\n\n", user.BindIP, serverNetMask))
	}

	// 可以添加其他配置，如路由推送等
	config.WriteString("# 其他配置可以在这里添加\n")
	config.WriteString("# push \"route 192.168.1.0 255.255.255.0\"\n")
	config.WriteString("# push \"redirect-gateway def1\"\n")

	// 写入配置文件
	if err := os.WriteFile(ccdFile, []byte(config.String()), 0644); err != nil {
		return fmt.Errorf("failed to write CCD config file %s: %v", ccdFile, err)
	}

	fmt.Printf("Created CCD config for user %s (CN: %s) with IP %s\n",
		user.Name, user.CertCN, user.BindIP)

	return nil
}

// deleteCCDConfig 删除用户的CCD配置文件
func (cm *CCDManager) deleteCCDConfig(user types.User) error {
	if user.CertCN == "" {
		return nil // 没有CN，无需删除
	}

	ccdFile := filepath.Join(cm.ccdDir, user.CertCN)

	// 检查文件是否存在
	if _, err := os.Stat(ccdFile); os.IsNotExist(err) {
		return nil // 文件不存在，无需删除
	}

	// 删除文件
	if err := os.Remove(ccdFile); err != nil {
		return fmt.Errorf("failed to remove CCD config file %s: %v", ccdFile, err)
	}

	fmt.Printf("Deleted CCD config for user %s (CN: %s)\n", user.Name, user.CertCN)
	return nil
}

// getServerNetMask 获取服务器虚拟网段的子网掩码
func (cm *CCDManager) getServerNetMask() (string, error) {
	config, err := dataStore.GetVPNConfig()
	if err != nil {
		return "", fmt.Errorf("failed to get VPN config: %v", err)
	}

	return config.ServerNet.Mask, nil
}

// ValidateCCDConfig 验证CCD配置的有效性
func (cm *CCDManager) ValidateCCDConfig(users []types.User) error {
	// 检查用户的bindIP是否在服务器虚拟网段内
	serverNetMask, err := cm.getServerNetMask()
	if err != nil {
		return fmt.Errorf("failed to get server net mask: %v", err)
	}

	for _, user := range users {
		if user.Enable && user.BindIP != "" {
			// 这里可以添加IP地址范围验证逻辑
			// 验证用户IP是否在服务器虚拟网段内
			if err := cm.validateIPInServerNet(user.BindIP, serverNetMask); err != nil {
				return fmt.Errorf("user %s IP validation failed: %v", user.Name, err)
			}
		}
	}

	return nil
}

// validateIPInServerNet 验证IP是否在服务器虚拟网段内
func (cm *CCDManager) validateIPInServerNet(clientIP, netMask string) error {
	// 这里可以实现IP地址范围验证
	// 目前只做基本的格式检查
	if clientIP == "" {
		return fmt.Errorf("client IP cannot be empty")
	}

	// 简单的IP格式验证
	parts := strings.Split(clientIP, ".")
	if len(parts) != 4 {
		return fmt.Errorf("invalid IP format: %s", clientIP)
	}

	return nil
}
