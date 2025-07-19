package conf

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/ini.v1"
    . "iotvpn_config_manager_plugin/nanomq/pkg/log"
)

type TLSConf struct {
	TLSEnable           bool   `json:"tls.enable"`
	TLSUrl              string `json:"tls.url"`
	TLSKeyFile          string `json:"tls.keyfile"`
	TLSCertFile         string `json:"tls.certfile"`
	TLSCaCertFile       string `json:"tls.cacertfile"`
	TLSVerifyPeer       bool   `json:"tls.verify_peer"`
	TLSFailIfNoPeerCert bool   `json:"tls.fail_if_no_peer_cert"`

	// TLSUrl = TLSPortPrefix:TLSPort
	TLSPort       int    `json:"-"`
	TLSPortPrefix string `json:"-"`
}

type HTTPConf struct {
	HTTPServerEnable            bool   `json:"http_server.enable"`
	HTTPServerPort              int    `json:"http_server.port"`
	HTTPServerParallel          int    `json:"http_server.parallel"`
	HTTPServerUsername          string `json:"http_server.username"`
	HTTPServerPassword          string `json:"http_server.password"`
	HTTPServerAuthType          string `json:"http_server.auth_type"`
	HTTPServerJWTPublicKeyfile  string `json:"http_server.jwt.public.keyfile"`
	HTTPServerJWTPrivateKeyfile string `json:"http_server.jwt.private.keyfile"`
}

type LogConf struct {
	LogTo            string `json:"log.to"`
	LogLevel         string `json:"log.level"`
	LogDir           string `json:"log.dir"`
	LogFile          string `json:"log.file"`
	LogRotationSize  string `json:"log.rotation.size"`
	LogRotationCount int    `json:"log.rotation.count"`
}

type AuthLogin struct {
	// auth.n.login = admin
	// auth.n.password = public
	Login    string `json:"auth.id.login"`
	Password string `json:"auth.id.password"`
}

type AuthHTTP struct {
	AuthHTTPEnable bool `json:"auth.http.enable"`
}

type ACLRule struct {
	Permit string `json:"permit"`
	// ipaddr,clientid,username 三选一
	IPAddr   string `json:"ipaddr,omitempty"`
	ClientID string `json:"clientid,omitempty"`
	Username string `json:"username,omitempty"`

	Action string   `json:"action,omitempty"`
	Topics []string `json:"topics,omitempty"`
}

type ACLConf struct {
	ACLEnable      bool   `json:"acl_enable"`
	ACLNoMatch     string `json:"acl_nomatch"`
	EnableACLCache string `json:"enable_acl_cache"`
	ACLacheMaxSize int    `json:"acl_cache_max_size"`
	ACLCacheTTL    string `json:"acl_cache_ttl"`
	ACLDenyAction  string `json:"acl_deny_action"`

	// acl.rule.1={"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}
	ACLRuleList []ACLRule `json:"acl.rule"`
}

type AuthConf struct {
	AuthHTTP
	AuthLoginList []AuthLogin `json:"auth.login"`
}

type NanoMQConf struct {
	TLSConf
	HTTPConf
	LogConf
	ACLConf
	AuthConf

	filepath   string       `json:"-"`
	iniFile    *ini.File    `json:"-"`
	iniSection *ini.Section `json:"-"`

	mu sync.Mutex
}

func (c *NanoMQConf) parseTLSConf(sec *ini.Section) {
	c.TLSEnable, _ = sec.Key("tls.enable").Bool()
	c.TLSUrl = sec.Key("tls.url").String()
	c.TLSKeyFile = sec.Key("tls.keyfile").String()
	c.TLSCertFile = sec.Key("tls.certfile").String()
	c.TLSCaCertFile = sec.Key("tls.cacertfile").String()
	c.TLSVerifyPeer, _ = sec.Key("tls.verify_peer").Bool()
	c.TLSFailIfNoPeerCert, _ = sec.Key("tls.fail_if_no_peer_cert").Bool()

	if index := strings.LastIndexByte(c.TLSUrl, ':'); index != -1 && !strings.HasSuffix(c.TLSUrl, ":") {
		port := c.TLSUrl[index+1:]
		c.TLSPort, _ = strconv.Atoi(port)
		c.TLSPortPrefix = c.TLSUrl[0:index]
	}
}

func (c *NanoMQConf) syncTLSConf(sec *ini.Section) {
	sec.Key("tls.enable").SetValue(fmt.Sprint(c.TLSEnable))
	sec.Key("tls.url").SetValue(c.TLSUrl)
	sec.Key("tls.keyfile").SetValue(c.TLSKeyFile)
	sec.Key("tls.certfile").SetValue(c.TLSCertFile)
	sec.Key("tls.cacertfile").SetValue(c.TLSCaCertFile)
	sec.Key("tls.verify_peer").SetValue(fmt.Sprint(c.TLSVerifyPeer))
	sec.Key("tls.fail_if_no_peer_cert").SetValue(fmt.Sprint(c.TLSFailIfNoPeerCert))
}

func (c *NanoMQConf) parseHTTPConf(sec *ini.Section) {
	c.HTTPServerEnable, _ = sec.Key("http_server.enable").Bool()
	c.HTTPServerPort, _ = sec.Key("http_server.port").Int()
	c.HTTPServerParallel, _ = sec.Key("http_server.parallel").Int()
	c.HTTPServerUsername = sec.Key("http_server.username").String()
	c.HTTPServerPassword = sec.Key("http_server.password").String()
	c.HTTPServerAuthType = sec.Key("http_server.auth_type").String()
	c.HTTPServerJWTPublicKeyfile = sec.Key("http_server.jwt.public.keyfile").String()
	c.HTTPServerJWTPrivateKeyfile = sec.Key("http_server.jwt.private.keyfile").String()
}

func (c *NanoMQConf) syncHTTPConf(sec *ini.Section) {
	sec.Key("http_server.enable").SetValue(fmt.Sprint(c.HTTPServerEnable))
	sec.Key("http_server.port").SetValue(fmt.Sprint(c.HTTPServerPort))
	sec.Key("http_server.parallel").SetValue(fmt.Sprint(c.HTTPServerParallel))
	sec.Key("http_server.username").SetValue(c.HTTPServerUsername)
	sec.Key("http_server.password").SetValue(c.HTTPServerPassword)
	sec.Key("http_server.auth_type").SetValue(c.HTTPServerAuthType)
	sec.Key("http_server.jwt.public.keyfile").SetValue(c.HTTPServerJWTPublicKeyfile)
	sec.Key("http_server.jwt.private.keyfile").SetValue(c.HTTPServerJWTPrivateKeyfile)
}

func (c *NanoMQConf) parseLogConf(sec *ini.Section) {
	c.LogTo = sec.Key("log.to").String()
	c.LogLevel = sec.Key("log.level").String()
	c.LogDir = sec.Key("log.dir").String()
	c.LogFile = sec.Key("log.file").String()
	c.LogRotationSize = sec.Key("log.rotation.size").String()
	c.LogRotationCount, _ = sec.Key("log.rotation.count").Int()
}

func (c *NanoMQConf) syncLogConf(sec *ini.Section) {
	sec.Key("log.to").SetValue(c.LogTo)
	sec.Key("log.level").SetValue(c.LogLevel)
	sec.Key("log.dir").SetValue(c.LogDir)
	sec.Key("log.file").SetValue(c.LogFile)
	sec.Key("log.rotation.size").SetValue(c.LogRotationSize)
	sec.Key("log.rotation.count").SetValue(fmt.Sprint(c.LogRotationCount))
}

func (c *NanoMQConf) parseACLConf(sec *ini.Section) {
	c.ACLEnable, _ = sec.Key("acl_enable").Bool()
	c.ACLNoMatch = sec.Key("acl_nomatch").String()
	c.EnableACLCache = sec.Key("enable_acl_cache").String()
	c.ACLacheMaxSize, _ = sec.Key("acl_cache_max_size").Int()
	c.ACLCacheTTL = sec.Key("acl_cache_ttl").String()
	c.ACLDenyAction = sec.Key("acl_deny_action").String()

	for id := 1; ; id++ {
		key := fmt.Sprintf("acl.rule.%d", id)
		if !sec.HasKey(key) {
			break
		}
		val := sec.Key(key).Value()

		var rule ACLRule
		if err := json.Unmarshal([]byte(val), &rule); err != nil {
			LogError("json.Unmarshal error: %v", err)
			continue
		}
		c.ACLRuleList = append(c.ACLRuleList, rule)
	}
}

func (c *NanoMQConf) syncACLConf(sec *ini.Section) {
	sec.Key("acl_enable").SetValue(fmt.Sprint(c.ACLEnable))
	sec.Key("acl_nomatch").SetValue(c.ACLNoMatch)
	sec.Key("enable_acl_cache").SetValue(c.EnableACLCache)
	sec.Key("acl_cache_max_size").SetValue(fmt.Sprint(c.ACLacheMaxSize))
	sec.Key("acl_cache_ttl").SetValue(c.ACLCacheTTL)
	sec.Key("acl_deny_action").SetValue(c.ACLDenyAction)

	for id, item := range c.ACLRuleList {
		key := fmt.Sprintf("acl.rule.%d", id+1)
		val, err := json.Marshal(item)
		if err != nil {
			LogError("json.Marshal: %+v error: %v\n", item, err)
			continue
		}
		sec.Key(key).SetValue(string(val))
	}

	// 删除多余旧的配置 （列表项个数减少情况）
	for id := len(c.ACLRuleList); ; id++ {
		key := fmt.Sprintf("acl.rule.%d", id+1)
		if !sec.HasKey(key) {
			break
		}
		sec.DeleteKey(key)
	}
}

func (c *NanoMQConf) parseAuthConf(sec *ini.Section) {
	for id := 1; ; id++ {
		loginKey := fmt.Sprintf("auth.%d.login", id)
		if !sec.HasKey(loginKey) {
			break
		}
		loginVal := sec.Key(loginKey).Value()
		passwdKey := fmt.Sprintf("auth.%d.password", id)
		passwdVal := sec.Key(passwdKey).Value()

		var auth = AuthLogin{Login: loginVal, Password: passwdVal}
		c.AuthLoginList = append(c.AuthLoginList, auth)
	}

	c.AuthHTTPEnable, _ = sec.Key("auth.http.enable").Bool()
}

func (c *NanoMQConf) syncAuthConf(sec *ini.Section) {
	var key, val string
	for id, item := range c.AuthLoginList {
		key = fmt.Sprintf("auth.%d.login", id+1)
		val = item.Login
		sec.Key(key).SetValue(val)

		key = fmt.Sprintf("auth.%d.password", id+1)
		val = item.Password
		sec.Key(key).SetValue(val)
	}

	// 删除多余旧的配置 （列表项个数减少情况）
	for id := len(c.AuthLoginList); ; id++ {
		key = fmt.Sprintf("auth.%d.login", id+1)
		if !sec.HasKey(key) {
			break
		}
		sec.DeleteKey(key)
		key = fmt.Sprintf("auth.%d.password", id+1)
		sec.DeleteKey(key)
	}

	sec.Key("auth.http.enable").SetValue(fmt.Sprint(c.AuthHTTPEnable))
}

func (c *NanoMQConf) String() string {
	data, _ := json.MarshalIndent(c, "", "  ")
	return string(data)
}

func NewNanoMQConfig(filepath string) (*NanoMQConf, error) {

	iniFile, err := ini.LoadSources(ini.LoadOptions{IgnoreInlineComment: true}, filepath)
	if err != nil {
		LogError("%v\n", err)
		return nil, err
	}

	iniSection, err := iniFile.GetSection("")
	if err != nil {
		LogError("%s: ini get section error: %v\n", filepath, err)
		return nil, err
	}

	return &NanoMQConf{
		filepath:   filepath,
		iniFile:    iniFile,
		iniSection: iniSection,
	}, nil
}

func (c *NanoMQConf) Parse() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.parseTLSConf(c.iniSection)
	c.parseHTTPConf(c.iniSection)
	c.parseLogConf(c.iniSection)
	c.parseACLConf(c.iniSection)
	c.parseAuthConf(c.iniSection)
	return nil
}

func (c *NanoMQConf) Sync() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.syncTLSConf(c.iniSection)
	c.syncHTTPConf(c.iniSection)
	c.syncLogConf(c.iniSection)
	c.syncACLConf(c.iniSection)
	c.syncAuthConf(c.iniSection)
	err := c.iniFile.SaveTo(c.filepath)
	if err != nil {
		LogError("%s: ini.SaveTo error: %v\n", c.filepath, err)
		return err
	}
	return nil
}
