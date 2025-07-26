package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"iotvpn_config_manager_plugin/sslvpn/pkg/types"
	"strconv"
	"strings"
)

// 全局防火墙管理器实例
var firewallManager *FirewallManager

// 初始化防火墙管理器
func initFirewallManager() {
	if firewallManager == nil {
		firewallManager = NewFirewallManager()
		firewallManager.Initialize()
	}
}

// 检查客户端CN是否重复
func UserCNIsUnique(users []types.User) (bool, string, error) {
	cnMap := make(map[string]string) // CN -> UserUUID

	for _, user := range users {
		// CertCN现在是必填字段，直接使用它
		cn := user.CertCN

		// 检查CN是否重复
		if existingUserUUID, exists := cnMap[cn]; exists {
			return false, fmt.Sprintf("CN '%s' is duplicated between users %s and %s", cn, existingUserUUID, user.UUID), nil
		}

		cnMap[cn] = user.UUID
	}

	return true, "", nil
}

// 从证书内容解析CN
func parseCNFromCert(certData string) (string, error) {
	// 如果是base64编码，先解码
	var certBytes []byte
	var err error

	if isBase64(certData) {
		certBytes, err = base64.StdEncoding.DecodeString(certData)
		if err != nil {
			return "", fmt.Errorf("failed to decode base64 certificate: %v", err)
		}
	} else {
		certBytes = []byte(certData)
	}

	// 解析PEM格式
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	// 解析X.509证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse X.509 certificate: %v", err)
	}

	// 提取CN
	return cert.Subject.CommonName, nil
}

// 检查字符串是否是base64编码
func isBase64(s string) bool {
	// 简单检查：base64字符串通常以特定字符结尾，且长度符合base64规则
	if len(s) == 0 {
		return false
	}

	// 检查是否包含base64字符
	base64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, char := range s {
		if !strings.ContainsRune(base64Chars, char) {
			return false
		}
	}

	// 长度必须是4的倍数
	return len(s)%4 == 0
}

// 调整防火墙规则的主函数
func AdjustFirewall(authorities *types.AuthoRuleGet) error {
	// 初始化防火墙管理器
	initFirewallManager()

	// 调整防火墙规则
	return firewallManager.AdjustFirewall(authorities)
}

// 清理防火墙规则
func CleanupFirewall() error {
	if firewallManager != nil {
		return firewallManager.Cleanup()
	}
	return nil
}

// 验证用户列表的完整性
func ValidateUsers(users []types.User) error {
	// 1. 检查CN是否重复
	isUnique, message, err := UserCNIsUnique(users)
	if err != nil {
		return fmt.Errorf("failed to check CN uniqueness: %v", err)
	}
	if !isUnique {
		return fmt.Errorf("CN validation failed: %s", message)
	}

	// 3. UUID Name  bindip 重复性检查
	uuidMap := make(map[string]string)
	nameMap := make(map[string]string)
	bindIPMap := make(map[string]string)

	for _, user := range users {

		// 2. 检查必要字段
		if user.UUID == "" {
			return fmt.Errorf("user UUID cannot be empty")
		}
		if user.Name == "" {
			return fmt.Errorf("user name cannot be empty for user %s", user.UUID)
		}
		if user.BindIP == "" {
			return fmt.Errorf("user %s must have a bind IP", user.Name)
		}

		//关键字段唯一性检查
		if _, exists := uuidMap[user.UUID]; exists {
			return fmt.Errorf("user UUID %s is duplicated", user.UUID)
		}
		uuidMap[user.UUID] = ""

		if _, exists := nameMap[user.Name]; exists {
			return fmt.Errorf("user name %s is duplicated", user.Name)
		}
		nameMap[user.Name] = ""

		if _, exists := bindIPMap[user.BindIP]; exists {
			return fmt.Errorf("user bind IP %s is duplicated", user.BindIP)
		}
		bindIPMap[user.BindIP] = ""
	}

	// 4. 检查用户bindIP是否在虚拟网段内
	if err := validateUserBindIPsInServerNet(users); err != nil {
		return err
	}

	// 服务端保留的ip，不允许用户使用
	if err := validateUserBindIPIsReserved(users); err != nil {
		return err
	}

	return nil
}

// validateUserBindIPIsReserved 网段前两个ip 和 后两个ip 不允许用户使用
func validateUserBindIPIsReserved(users []types.User) error {
	// 获取当前的VPN配置以获取虚拟网段信息
	config, err := dataStore.GetVPNConfig()
	if err != nil {
		return fmt.Errorf("failed to get VPN config: %v", err)
	}

	// 解析虚拟网段
	networkIP := parseIP(config.ServerNet.Net)
	if networkIP == nil {
		return fmt.Errorf("invalid network address: %s", config.ServerNet.Net)
	}

	subnetMask := parseIP(config.ServerNet.Mask)
	if subnetMask == nil {
		return fmt.Errorf("invalid subnet mask: %s", config.ServerNet.Mask)
	}

	// 计算网段范围
	networkAddr := ipAnd(networkIP, subnetMask)

	// 计算网关IP (通常是网络地址+1)
	gatewayIP := make([]byte, 4)
	copy(gatewayIP, networkAddr)
	gatewayIP[3] += 1

	// 计算广播地址
	broadcastAddr := make([]byte, 4)
	invertedMask := make([]byte, 4)
	for i := 0; i < 4; i++ {
		invertedMask[i] = ^subnetMask[i]
		broadcastAddr[i] = networkAddr[i] | invertedMask[i]
	}

	// 检查每个用户的绑定IP
	for _, user := range users {
		if user.BindIP == "" {
			continue
		}

		userIP := parseIP(user.BindIP)
		if userIP == nil {
			return fmt.Errorf("user %s has invalid IP address: %s", user.Name, user.BindIP)
		}

		// 检查是否是网关IP
		if ipEqual(userIP, gatewayIP) {
			return fmt.Errorf("user %s has IP %s which is the gateway IP (reserved)",
				user.Name, user.BindIP)
		}

		// 检查是否是广播IP
		if ipEqual(userIP, broadcastAddr) {
			return fmt.Errorf("user %s has IP %s which is the broadcast address (reserved)",
				user.Name, user.BindIP)
		}
	}

	return nil
}

// isIPInNetwork 检查IP地址是否在指定的网段内
func isIPInNetwork(ip, networkAddr, subnetMask []byte) bool {
	// 计算IP地址的网络部分
	ipNetwork := ipAnd(ip, subnetMask)

	// 比较IP地址的网络部分是否与网络地址相同
	return ipEqual(ipNetwork, networkAddr)
}

// ipEqual 比较两个IP地址是否相等
func ipEqual(ip1, ip2 []byte) bool {
	if ip1 == nil || ip2 == nil || len(ip1) != 4 || len(ip2) != 4 {
		return false
	}

	for i := 0; i < 4; i++ {
		if ip1[i] != ip2[i] {
			return false
		}
	}
	return true
}

// parseIP 将IP地址字符串解析为字节数组
func parseIP(ipStr string) []byte {
	parts := strings.Split(ipStr, ".")
	if len(parts) != 4 {
		return nil
	}

	ip := make([]byte, 4)
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return nil
		}
		ip[i] = byte(num)
	}

	return ip
}

// ipAnd 执行两个IP地址的按位与操作
func ipAnd(ip1, ip2 []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = ip1[i] & ip2[i]
	}
	return result
}

// ipOr 计算两个IP地址的按位或
func ipOr(ip1, ip2 []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = ip1[i] | ip2[i]
	}
	return result
}

// ipNot 计算IP地址的按位非
func ipNot(ip []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = ^ip[i]
	}
	return result
}

// ipInRange 检查IP地址是否在指定的范围内
func ipInRange(ip, start, end []byte) bool {
	for i := 0; i < 4; i++ {
		if ip[i] < start[i] || ip[i] > end[i] {
			return false
		}
		if ip[i] > start[i] || ip[i] < end[i] {
			break
		}
	}
	return true
}

// AdjustOpenVPNCCDConfig 调整OpenVPN CCD（Client Configuration Directory）配置
// 比较新旧用户列表，对CCD配置进行增删改操作
func AdjustOpenVPNCCDConfig(oldUsers, newUsers []types.User) error {
	// 使用CCD管理器来处理配置更新
	manager := NewCCDManager()
	return manager.UpdateConfigs(oldUsers, newUsers)

}

// findUserByUUID 根据UUID查找用户
func findUserByUUID(users []types.User, uuid string) *types.User {
	for _, user := range users {
		if user.UUID == uuid {
			return &user
		}
	}
	return nil
}

// validateUserBindIPsInServerNet 验证用户的bindIP是否在虚拟网段内
func validateUserBindIPsInServerNet(users []types.User) error {
	// 获取当前的VPN配置以获取虚拟网段信息
	config, err := dataStore.GetVPNConfig()
	if err != nil {
		return fmt.Errorf("failed to get VPN config: %v", err)
	}

	// 解析虚拟网段
	networkIP := parseIP(config.ServerNet.Net)
	subnetMask := parseIP(config.ServerNet.Mask)

	if networkIP == nil || subnetMask == nil {
		return fmt.Errorf("invalid server network configuration: net=%s, mask=%s",
			config.ServerNet.Net, config.ServerNet.Mask)
	}

	// 计算网段范围
	networkAddr := ipAnd(networkIP, subnetMask)
	broadcastAddr := ipOr(networkAddr, ipNot(subnetMask))

	// 验证每个用户的bindIP
	for _, user := range users {
		if user.BindIP == "" {
			continue
		}

		userIP := parseIP(user.BindIP)
		if userIP == nil {
			return fmt.Errorf("invalid bind IP format for user %s: %s", user.Name, user.BindIP)
		}

		// 检查IP是否在网段内
		if !ipInRange(userIP, networkAddr, broadcastAddr) {
			return fmt.Errorf("user %s bind IP %s is not in server network %s/%s",
				user.Name, user.BindIP, config.ServerNet.Net, config.ServerNet.Mask)
		}
	}

	return nil
}
