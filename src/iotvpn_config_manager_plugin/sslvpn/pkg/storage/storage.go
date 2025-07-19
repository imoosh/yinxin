package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"iotvpn_config_manager_plugin/sslvpn/pkg/defines"
	"iotvpn_config_manager_plugin/sslvpn/pkg/types"
)

// DataStore 数据存储器
type DataStore struct {
	dataDir    string
	userFile   string
	resFile    string
	authFile   string
	configFile string
	mutex      sync.RWMutex
}

// NewDataStore 创建数据存储器
func NewDataStore() *DataStore {
	return &DataStore{
		dataDir:    defines.SSLVPNDir,
		userFile:   defines.UserFile,
		resFile:    defines.ResFile,
		authFile:   defines.AuthFile,
		configFile: defines.SSLVPNConfigFile,
	}
}

// 数据存储结构
type StorageData struct {
	Users      []types.User
	Resources  []types.Resource
	Authority  types.AuthoRuleSet
	LastUpdate time.Time
}

// SetVPNConfig 保存VPN配置到JSON文件
func (ds *DataStore) SetVPNConfig(config *types.VPNConfig) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	// 设置更新时间
	configData := struct {
		Config     *types.VPNConfig `json:"config"`
		LastUpdate time.Time        `json:"last_update"`
	}{
		Config:     config,
		LastUpdate: time.Now(),
	}

	// 序列化为JSON
	data, err := json.MarshalIndent(configData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal VPN config: %v", err)
	}

	// 写入文件
	if err := os.WriteFile(ds.configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write VPN config file: %v", err)
	}

	return nil
}

// GetVPNConfig 从JSON文件读取VPN配置
func (ds *DataStore) GetVPNConfig() (*types.VPNConfig, error) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	// 检查文件是否存在
	if _, err := os.Stat(ds.configFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("VPN config file not found")
	}

	// 读取文件
	data, err := os.ReadFile(ds.configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read VPN config file: %v", err)
	}

	// 解析JSON
	var configData struct {
		Config     *types.VPNConfig `json:"config"`
		LastUpdate time.Time        `json:"last_update"`
	}

	if err := json.Unmarshal(data, &configData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VPN config: %v", err)
	}

	return configData.Config, nil
}

// User management
func (ds *DataStore) GetUsers() ([]types.User, error) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	return ds.loadUsers()
}

func (ds *DataStore) SetUsers(users []types.User) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	return ds.saveUsers(users)
}

// Resource management
func (ds *DataStore) GetResources() ([]types.Resource, error) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	return ds.loadResources()
}

func (ds *DataStore) SetResources(resources []types.Resource) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	return ds.saveResources(resources)
}

func (ds *DataStore) SetAuthority(authority types.AuthoRuleSet) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	return ds.saveAuthority(authority)
}

// GetAuthority 获取权限配置详情
func (ds *DataStore) GetAuthority() (*types.AuthoRuleGet, error) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	authority, err := ds.loadAuthority()
	if err != nil {
		return nil, err
	}

	//填充详情
	users, err := ds.GetUsers()
	if err != nil {
		return nil, err
	}
	resources, err := ds.GetResources()
	if err != nil {
		return nil, err
	}

	userMap := make(map[string]types.User)
	for _, user := range users {
		userMap[user.UUID] = user
	}
	resourceMap := make(map[string]types.Resource)
	for _, resource := range resources {
		resourceMap[resource.UUID] = resource
	}

	var ret types.AuthoRuleGet
	ret.Enable = authority.Enable
	ret.Auth = make([]types.AuthRuleVerboseOne, len(authority.Auth))
	for i, auth := range authority.Auth {
		ret.Auth[i].User = userMap[auth.UserUUID]
		for _, resourceUUID := range auth.ResourceUUIDs {
			ret.Auth[i].Resources = append(ret.Auth[i].Resources, resourceMap[resourceUUID])
		}
	}
	return &ret, nil
}

// 私有方法：加载和保存数据
func (ds *DataStore) loadUsers() ([]types.User, error) {
	var users []types.User
	if err := ds.loadFromFile(ds.userFile, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (ds *DataStore) saveUsers(users []types.User) error {
	return ds.saveToFile(ds.userFile, users)
}

func (ds *DataStore) loadResources() ([]types.Resource, error) {
	var resources []types.Resource
	if err := ds.loadFromFile(ds.resFile, &resources); err != nil {
		return nil, err
	}
	return resources, nil
}

func (ds *DataStore) saveResources(resources []types.Resource) error {
	return ds.saveToFile(ds.resFile, resources)
}

// loadAuthority 直接返回uuid之前的关联 ，外面填充
func (ds *DataStore) loadAuthority() (types.AuthoRuleSet, error) {
	var authority types.AuthoRuleSet
	if err := ds.loadFromFile(ds.authFile, &authority); err != nil {
		return types.AuthoRuleSet{}, err
	}
	return authority, nil
}

func (ds *DataStore) saveAuthority(authority types.AuthoRuleSet) error {
	return ds.saveToFile(ds.authFile, authority)
}

func (ds *DataStore) loadFromFile(filename string, v interface{}) error {
	if _, err := os.Stat(filename); err != nil {
		return fmt.Errorf("file not found: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", filename, err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal data from %s: %v", filename, err)
	}

	return nil
}

func (ds *DataStore) saveToFile(filename string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %v", filename, err)
	}

	return nil
}

// initializeDefaultVPNConfig 初始化默认VPN配置
func (ds *DataStore) initializeDefaultVPNConfig() error {
	// 检查配置文件是否存在
	if _, err := os.Stat(ds.configFile); err == nil {
		return nil // 文件已存在，无需初始化
	}

	// 创建默认配置
	defaultConfig := &types.VPNConfig{
		Port:             1194,
		MaxClients:       100,
		Verb:             3,
		DataCiphers:      []string{"AES-256-GCM", "AES-128-GCM"},
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

	// 保存默认配置
	return ds.SetVPNConfig(defaultConfig)
}
