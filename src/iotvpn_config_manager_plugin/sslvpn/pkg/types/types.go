package types

import "github.com/go-playground/validator/v10"

// 基础响应结构
type BaseResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"message"`
	Data interface{} `json:"result"`
}

// 错误响应结构
type ErrorResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"message"`
	Data interface{} `json:"result"`
}

// 服务状态响应数据
type StatusData struct {
	CfgIsDefault  bool `json:"cfg_is_default"`
	CfgStatus     bool `json:"cfg_status"`
	ServiceStatus bool `json:"service_status"`
}

// 版本信息响应数据
type VersionData struct {
	Version   string `json:"version"`
	Build     string `json:"build"`
	GitHash   string `json:"git_hash"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// 路由配置
type RouteConfig struct {
	Net  string `json:"net" validate:"required,ipv4"`
	Mask string `json:"mask" validate:"required,ipv4"`
}

// 虚拟网段配置
type ServerNet struct {
	Net  string `json:"net" validate:"required,ipv4"`  // 网段地址，如 "192.168.1.0"
	Mask string `json:"mask" validate:"required,ipv4"` // 子网掩码，如 "255.255.255.0"
}

// VPN配置
type VPNConfig struct {
	Port             int           `json:"port" validate:"required,min=1,max=65535"`
	MaxClients       int           `json:"max-clients" validate:"required,min=1"`
	Verb             int           `json:"verb" validate:"min=1,max=13"`
	DataCiphers      []string      `json:"data-ciphers" validate:"required,min=1,dive,required"`
	PushDNS          string        `json:"push_dns" validate:"omitempty,ipv4"`
	PushRouteDefault bool          `json:"push_route_default"`
	PushRoute        []RouteConfig `json:"push_route" validate:"dive"`
	ServerNet        ServerNet     `json:"server_net" validate:"required"`
}

// 用户信息
type User struct {
	UUID     string `json:"uuid" validate:"required,uuid"`
	Name     string `json:"name" validate:"required"`
	Enable   bool   `json:"enable"`
	CertCN   string `json:"cert_CN" validate:"required"` //用户也可能直接输入证书CN
	PhoneNum string `json:"phone_num" validate:"omitempty"`
	BindIP   string `json:"bind_ip" validate:"omitempty,ipv4"`
}

// 资源信息
type Resource struct {
	UUID   string `json:"uuid" validate:"required,uuid"`
	Name   string `json:"name" validate:"required"`
	Enable bool   `json:"enable"`
	IP     string `json:"ip" validate:"required,ipv4"`
}

// set-authority 接口的json
type AuthoRuleSet struct {
	Enable bool          `json:"enable"`
	Auth   []AuthRuleOne `json:"auth" validate:"dive"`
}

// 权限规则 下发时，只包含uuid
type AuthRuleOne struct {
	UserUUID      string   `json:"user_uuid" validate:"required,uuid"`
	ResourceUUIDs []string `json:"resource_uuids,omitempty" validate:"dive,uuid"`
}

// get-authority 接口的json
type AuthoRuleGet struct {
	Enable bool                 `json:"enable"`
	Auth   []AuthRuleVerboseOne `json:"auth" validate:"dive"`
}

// 权限规则 查询时，包含详细信息
type AuthRuleVerboseOne struct {
	User      User       `json:"user,omitempty" validate:"dive,uuid"`
	Resources []Resource `json:"resources,omitempty" validate:"dive"`
}

// 证书4项 ca cert key crl
type PluginCertManagerJson struct {
	CA     string `json:"ca" validate:"required,base64"`
	Cert   string `json:"cert" validate:"required,base64"`
	Key    string `json:"key" validate:"required,base64"`
	KeyPwd string `json:"key_pwd"`
	Crl    string `json:"crl" validate:"omitempty,base64"`
}

// ValidateStruct performs validation on the struct
func ValidateStruct(s interface{}) error {
	validate := validator.New()
	return validate.Struct(s)
}
