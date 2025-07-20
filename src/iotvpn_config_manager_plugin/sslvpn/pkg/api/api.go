package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"

	"iotvpn_config_manager_plugin/sslvpn/pkg/config"
	error_def "iotvpn_config_manager_plugin/sslvpn/pkg/error_def"
	"iotvpn_config_manager_plugin/sslvpn/pkg/pki"
	"iotvpn_config_manager_plugin/sslvpn/pkg/service"
	"iotvpn_config_manager_plugin/sslvpn/pkg/storage"
	"iotvpn_config_manager_plugin/sslvpn/pkg/types"
	"iotvpn_config_manager_plugin/version"
)

// 全局实例
var (
	serviceManager     *service.ServiceManager
	configManager      *config.SSLVPNConfigManager
	dataStore          *storage.DataStore
	certificateManager *pki.CertificateManager
	initOnce           sync.Once
)

// 初始化管理器
func initManagers() {
	serviceManager = service.NewServiceManager()       //openvpn 服务管理
	configManager = config.NewConfigManager()          //openvpn 配置管理
	dataStore = storage.NewDataStore()                 //json 配置数据存储
	certificateManager = pki.NewCertificateManager("") //证书管理
}

func newErrorResponse(code int, customMsg string) *types.BaseResponse {
	return &types.BaseResponse{
		Code: code,
		Msg:  error_def.GetErrDesc(code, customMsg),
		Data: struct{}{},
	}
}

// GetVersion 获取版本信息
func GetVersion(input string) (*types.BaseResponse, error) {
	buildInfo := version.GetBuildInfo()
	data := types.VersionData{
		Version:   buildInfo.Version,
		Build:     buildInfo.Build,
		GitHash:   buildInfo.GitHash,
		GoVersion: buildInfo.GoVersion,
		OS:        buildInfo.OS,
		Arch:      buildInfo.Arch,
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, ""),
		Data: data,
	}, nil
}

// CheckStatus 检查服务状态
func CheckStatus(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	cfgIsDefault, cfgExists, serviceStatus, err := serviceManager.CheckStatus()
	if err != nil {
		return newErrorResponse(error_def.ErrInternal, err.Error()), nil
	}

	data := types.StatusData{
		CfgIsDefault:  cfgIsDefault,
		CfgStatus:     cfgExists,
		ServiceStatus: serviceStatus,
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, ""),
		Data: data,
	}, nil
}

// GenerateDefaultConfig 生成默认配置
func GenerateDefaultConfig(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	config, err := configManager.GenerateDefaultConfig()
	if err != nil {
		return newErrorResponse(error_def.ErrInternal, err.Error()), nil
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, "default config generated successfully"),
		Data: config,
	}, nil
}

// RestartService 重启服务
func RestartService(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	//1 启用系统转发 echo 1 > /proc/sys/net/ipv4/ip_forward
	cmd := exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	if err := cmd.Run(); err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to enable system forwarding: %v", err)), nil
	}

	//2 获取vpnconfig用于添加NAT规则
	vpnconfig, err := dataStore.GetVPNConfig()
	if err != nil {
		return newErrorResponse(error_def.ErrInternal, err.Error()), nil
	}
	//  转换成cidr格式  192.168.1.0 255.255.255.0  -> 192.168.1.0/24
	cidrNet, err := convertNetmaskToCIDR(vpnconfig.ServerNet.Net, vpnconfig.ServerNet.Mask)
	if err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to convert network to CIDR: %v", err)), nil
	}
	//   添加NAT规则
	err = addNATRule(cidrNet)
	if err != nil {
		//   NAT规则添加失败，记录日志但不影响服务重启结果
		// fmt.Printf("Warning: Failed to add NAT rule for %s: %v\n", cidrNet, err)
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to add NAT rule: %v", err)), nil
	}

	//3 重启服务
	err = serviceManager.RestartService(input)
	if err != nil {
		return newErrorResponse(error_def.ErrInternal, err.Error()), nil
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, "service restarted successfully"),
		Data: struct{}{},
	}, nil
}

// SetConfig 设置VPN配置
func SetConfig(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	if input == "" {
		return newErrorResponse(error_def.ErrInvalidParam, "input cannot be empty"), nil
	}

	var config types.VPNConfig
	if err := json.Unmarshal([]byte(input), &config); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("invalid JSON input: %v", err)), nil
	}

	if err := types.ValidateStruct(&config); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("validation failed: %v", err)), nil
	}

	// 保存配置到JSON文件
	if err := dataStore.SetVPNConfig(&config); err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to save config to storage: %v", err)), nil
	}

	// 生成OpenVPN配置文件
	if err := configManager.GenOpenVPNConfFile(&config); err != nil {
		// OpenVPN配置生成失败，记录警告但不影响JSON存储
		fmt.Printf("Warning: failed to generate OpenVPN config: %v\n", err)
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("failed to generate OpenVPN config: %v", err)), nil
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, "config saved successfully"),
		Data: struct{}{},
	}, nil
}

// GetConfig 获取VPN配置
func GetConfig(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	// 从JSON文件读取配置
	config, err := dataStore.GetVPNConfig()
	if err != nil {
		// 如果JSON配置文件不存在，返回默认配置
		config = &types.VPNConfig{
			Port:       1194,
			MaxClients: 100,
			Verb:       3,
			DataCiphers: []string{
				"AES-256-GCM",
				"AES-128-GCM",
			},
			PushDNS:          "8.8.8.8",
			PushRouteDefault: false,
			PushRoute: []types.RouteConfig{
				{
					Net:  "10.8.0.0",
					Mask: "255.255.255.0",
				},
			},
			ServerNet: types.ServerNet{
				Net:  "192.168.1.0",
				Mask: "255.255.255.0",
			},
		}
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, ""),
		Data: config,
	}, nil
}

// SetUser 设置用户信息
func SetUser(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	if input == "" {
		return newErrorResponse(error_def.ErrInvalidParam, "input cannot be empty"), nil
	}

	// 获取旧用户信息
	oldUsers, err := dataStore.GetUsers()
	if err != nil {
		// 如果获取旧用户失败，记录警告但不影响用户保存
		fmt.Printf("Warning: failed to get old users for CCD update: %v\n", err)
		oldUsers = []types.User{}
	}

	var users []types.User
	if err := json.Unmarshal([]byte(input), &users); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("invalid JSON input: %v", err)), nil
	}

	for i := range users {
		if err := types.ValidateStruct(&users[i]); err != nil {
			return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("validation failed for user %s: %v", users[i].Name, err)), nil
		}
	}

	// 处理用户证书信息：从证书中解析CN，清空证书内容
	for i := range users {
		if err := SetUserEffectiveCN(&users[i]); err != nil {
			return newErrorResponse(error_def.ErrInvalidCert, fmt.Sprintf("failed to process certificate for user %s: %v", users[i].Name, err)), nil
		}
	}

	// 验证用户数据完整性（包括CN重复检查）
	if err := ValidateUsers(users); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("user validation failed: %v", err)), nil
	}

	// 保存用户信息
	if err := dataStore.SetUsers(users); err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to save users: %v", err)), nil
	}

	newUsers, err := dataStore.GetUsers()
	if err != nil {
		// 如果获取新用户失败，记录警告但不影响用户保存
		fmt.Printf("Warning: failed to get new users for CCD update: %v\n", err)
		newUsers = []types.User{}
	}

	// 更新CCD配置
	if err := AdjustOpenVPNCCDConfig(oldUsers, newUsers); err != nil {
		// CCD配置更新失败，记录错误但不影响用户数据保存
		fmt.Printf("Warning: failed to update CCD configuration: %v\n", err)
	}

	authorities, err := dataStore.GetAuthority()
	if err != nil {
		// 如果获取权限失败，记录警告但不影响用户保存
		fmt.Printf("Warning: failed to get authorities for firewall update: %v\n", err)
		authorities = &types.AuthoRuleGet{
			Enable: false,
			Auth:   []types.AuthRuleVerboseOne{},
		}
	}

	// 更新防火墙规则
	if err := AdjustFirewall(authorities); err != nil {
		// 防火墙更新失败，记录错误但不影响用户数据保存
		fmt.Printf("Warning: failed to update firewall rules: %v\n", err)
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, "users saved successfully"),
		Data: struct{}{},
	}, nil
}

// GetUser 获取用户信息
func GetUser(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	users, err := dataStore.GetUsers()
	if err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to get users: %v", err)), nil
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, ""),
		Data: users,
	}, nil
}

// SetResource 设置资源信息
func SetResource(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	if input == "" {
		return newErrorResponse(error_def.ErrInvalidParam, "input cannot be empty"), nil
	}

	var resources []types.Resource
	if err := json.Unmarshal([]byte(input), &resources); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("invalid JSON input: %v", err)), nil
	}

	for i := range resources {
		if err := types.ValidateStruct(&resources[i]); err != nil {
			return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("validation failed for resource %s: %v", resources[i].Name, err)), nil
		}
	}

	// 保存资源信息
	if err := dataStore.SetResources(resources); err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to save resources: %v", err)), nil
	}

	authorities, err := dataStore.GetAuthority()
	if err != nil {
		fmt.Printf("Warning: failed to get authorities for firewall update: %v\n", err)
		authorities = &types.AuthoRuleGet{
			Enable: false,
			Auth:   []types.AuthRuleVerboseOne{},
		}
	}

	// 更新防火墙规则
	if err := AdjustFirewall(authorities); err != nil {
		fmt.Printf("Warning: failed to update firewall rules: %v\n", err)
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, "resources saved successfully"),
		Data: struct{}{},
	}, nil
}

// GetResource 获取资源信息
func GetResource(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	resources, err := dataStore.GetResources()
	if err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to get resources: %v", err)), nil
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, ""),
		Data: resources,
	}, nil
}

// SetAuthority 设置权限规则
func SetAuthority(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	if input == "" {
		return newErrorResponse(error_def.ErrInvalidParam, "input cannot be empty"), nil
	}

	var authoritySet types.AuthoRuleSet
	if err := json.Unmarshal([]byte(input), &authoritySet); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("invalid JSON input: %v", err)), nil
	}

	if err := types.ValidateStruct(&authoritySet); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("validation failed: %v", err)), nil
	}

	// 保存权限规则
	if err := dataStore.SetAuthority(authoritySet); err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to save authority: %v", err)), nil
	}

	authVerbose, err := dataStore.GetAuthority()
	if err != nil {
		fmt.Printf("Warning: failed to get authority for firewall update: %v\n", err)
		authVerbose = &types.AuthoRuleGet{
			Enable: false,
			Auth:   []types.AuthRuleVerboseOne{},
		}
	}
	// 更新防火墙规则
	if err := AdjustFirewall(authVerbose); err != nil {
		fmt.Printf("Warning: failed to update firewall rules: %v\n", err)
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, "authority saved successfully"),
		Data: struct{}{},
	}, nil
}

// GetAuthority 获取权限规则
func GetAuthority(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	authority, err := dataStore.GetAuthority()
	if err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to get authority: %v", err)), nil
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, ""),
		Data: authority,
	}, nil
}

// SetCertAndOther 保存4项证书相关文件 ca  cert key crl
func SetCertAndOther(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	var certManagerJson types.PluginCertManagerJson
	if err := json.Unmarshal([]byte(input), &certManagerJson); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("invalid JSON input: %v", err)), nil
	}

	if err := types.ValidateStruct(&certManagerJson); err != nil {
		return newErrorResponse(error_def.ErrInvalidParam, fmt.Sprintf("validation failed: %v", err)), nil
	}

	if err := certificateManager.ParseAll(&certManagerJson); err != nil {
		return newErrorResponse(error_def.ErrInvalidCert, fmt.Sprintf("failed to parse certificate: %v", err)), nil
	}

	//保存
	if err := certificateManager.SaveAll(&certManagerJson); err != nil {
		return newErrorResponse(error_def.ErrInternal, fmt.Sprintf("failed to save certificate: %v", err)), nil
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, ""),
		Data: struct{}{},
	}, nil
}

// GetCertAndOther 获取4项证书相关文件 ca  cert key crl
//输出格式
/*
{
    "code": 0, //错误码
    "message": "code decribe msg", //错误描述
    "result": {
        "ca": "base64 encode file", //文件内容的base64
        "cert": "base64 encode file", //文件内容的base64
        "crl":""//文件内容的base64
    }
}

*/
func GetCertAndOther(input string) (*types.BaseResponse, error) {
	initOnce.Do(initManagers)

	ca, err := os.ReadFile(certificateManager.CAPath)
	if err != nil {
		return newErrorResponse(error_def.ErrNotFound, fmt.Sprintf("failed to get ca: %v", err)), nil
	}

	cert, err := os.ReadFile(certificateManager.CertPath)
	if err != nil {
		return newErrorResponse(error_def.ErrNotFound, fmt.Sprintf("failed to get cert: %v", err)), nil
	}

	crl, err := os.ReadFile(certificateManager.CrlPath)
	if err != nil {
		return newErrorResponse(error_def.ErrNotFound, fmt.Sprintf("failed to get crl: %v", err)), nil
	}

	// 将文件内容转为base64编码
	caBase64 := base64.StdEncoding.EncodeToString(ca)
	certBase64 := base64.StdEncoding.EncodeToString(cert)
	crlBase64 := base64.StdEncoding.EncodeToString(crl)

	// 按照注释要求的格式创建返回结果
	result := map[string]string{
		"ca":   caBase64,
		"cert": certBase64,
		"crl":  crlBase64,
	}

	return &types.BaseResponse{
		Code: error_def.ErrOk,
		Msg:  error_def.GetErrDesc(error_def.ErrOk, ""),
		Data: result,
	}, nil
}

// convertNetmaskToCIDR 将网络地址和子网掩码转换为CIDR格式
func convertNetmaskToCIDR(network, netmask string) (string, error) {
	// 解析子网掩码
	mask := net.IPMask(net.ParseIP(netmask).To4())
	if mask == nil {
		return "", fmt.Errorf("invalid netmask: %s", netmask)
	}

	// 计算CIDR前缀长度
	ones, _ := mask.Size()

	// 返回CIDR格式
	return fmt.Sprintf("%s/%d", network, ones), nil
}

// addNATRule 添加NAT规则
func addNATRule(cidrNet string) error {
	// 检查规则是否已存在
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", cidrNet, "-j", "MASQUERADE")
	if checkCmd.Run() == nil {
		// 规则已存在，不需要重复添加
		fmt.Printf("NAT rule for %s already exists\n", cidrNet)
		return nil
	}

	// 添加NAT规则
	addCmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cidrNet, "-j", "MASQUERADE")
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add NAT rule: %v", err)
	}

	fmt.Printf("Successfully added NAT rule for %s\n", cidrNet)
	return nil
}
