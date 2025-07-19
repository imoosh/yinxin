package api

import (
	"fmt"
	"iotvpn_config_manager_plugin/sslvpn/pkg/types"
	"os/exec"
	"strings"
	"sync"
)

// FirewallManager 防火墙管理器
type FirewallManager struct {
	mainChain         string
	customChainPrefix string
	tunInterface      string
	mutex             sync.Mutex
	initialized       bool
}

// NewFirewallManager 创建防火墙管理器
func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		mainChain:         "iot-vpn-config-agent",
		customChainPrefix: "iot-vpn-chain-",
		tunInterface:      "tun0",
		initialized:       false,
	}
}

// Initialize 初始化防火墙主链（幂等操作）
func (fm *FirewallManager) Initialize() error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if fm.initialized {
		return nil
	}

	// 1. 检查主链是否存在，不存在则创建
	if !fm.chainExists(fm.mainChain) {
		if err := fm.createChain(fm.mainChain); err != nil {
			return fmt.Errorf("failed to create main chain: %v", err)
		}
	}

	// 2. 检查并添加基础规则（幂等）
	if err := fm.ensureBaseRules(); err != nil {
		return fmt.Errorf("failed to ensure base rules: %v", err)
	}

	fm.initialized = true
	return nil
}

// AdjustFirewall 调整防火墙规则（原子操作）
func (fm *FirewallManager) AdjustFirewall(authorities *types.AuthoRuleGet) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	// 确保初始化
	if err := fm.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize firewall: %v", err)
	}

	// 1. 计算需要的用户链
	requiredChains := make(map[string]bool)
	for _, auth := range authorities.Auth {
		if auth.User.Enable && auth.User.BindIP != "" {
			chainName := fm.getChainName(auth.User.BindIP)
			requiredChains[chainName] = true
		}
	}

	// 2. 清理不需要的用户链
	if err := fm.cleanupUnusedChains(requiredChains); err != nil {
		return fmt.Errorf("failed to cleanup unused chains: %v", err)
	}

	// 3. 原子性更新每个用户的规则
	for _, auth := range authorities.Auth {
		if auth.User.Enable && auth.User.BindIP != "" {
			if err := fm.updateUserRulesAtomic(auth.User, auth.Resources); err != nil {
				return fmt.Errorf("failed to update rules for user %s: %v", auth.User.Name, err)
			}
		}
	}

	return nil
}

// updateUserRulesAtomic 原子性更新用户规则
func (fm *FirewallManager) updateUserRulesAtomic(user types.User, resources []types.Resource) error {
	chainName := fm.getChainName(user.BindIP)
	tempChainName := chainName + "-temp"

	// 1. 创建临时链
	if err := fm.createChain(tempChainName); err != nil {
		return fmt.Errorf("failed to create temp chain: %v", err)
	}

	// 2. 在临时链中构建规则
	if err := fm.buildUserRules(tempChainName, user, resources); err != nil {
		fm.deleteChain(tempChainName) // 清理临时链
		return fmt.Errorf("failed to build user rules: %v", err)
	}

	// 3. 原子性替换：更新主链中的跳转规则
	if err := fm.replaceUserChain(user.BindIP, chainName, tempChainName); err != nil {
		fm.deleteChain(tempChainName) // 清理临时链
		return fmt.Errorf("failed to replace user chain: %v", err)
	}

	// 4. 清理旧链
	if fm.chainExists(chainName) {
		fm.deleteChain(chainName)
	}

	// 5. 重命名临时链
	if err := fm.renameChain(tempChainName, chainName); err != nil {
		return fmt.Errorf("failed to rename temp chain: %v", err)
	}

	return nil
}

// buildUserRules 构建用户规则
func (fm *FirewallManager) buildUserRules(chainName string, user types.User, resources []types.Resource) error {
	// 1. 默认允许DNS
	if err := fm.addRule(chainName, "-p udp --dport 53 -j ACCEPT"); err != nil {
		return fmt.Errorf("failed to add DNS rule: %v", err)
	}

	// 2. 根据用户的资源权限添加访问规则
	for _, resource := range resources {
		if resource.Enable {
			rule := fmt.Sprintf("-d %s -j ACCEPT", resource.IP)
			if err := fm.addRule(chainName, rule); err != nil {
				return fmt.Errorf("failed to add resource rule: %v", err)
			}
		}
	}

	// 3. 最后拒绝其他流量
	if err := fm.addRule(chainName, "-j DROP"); err != nil {
		return fmt.Errorf("failed to add DROP rule: %v", err)
	}

	return nil
}

// ensureBaseRules 确保基础规则存在（幂等）
func (fm *FirewallManager) ensureBaseRules() error {
	rules := []string{
		"-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
		fmt.Sprintf("-A FORWARD -i %s -m state --state NEW -j %s", fm.tunInterface, fm.mainChain),
	}

	for _, rule := range rules {
		if !fm.ruleExists(rule) {
			if err := fm.executeIPTables(rule); err != nil {
				return fmt.Errorf("failed to add base rule: %v", err)
			}
		}
	}

	return nil
}

// 工具方法
func (fm *FirewallManager) chainExists(chainName string) bool {
	cmd := exec.Command("iptables", "-L", chainName, "-n")
	return cmd.Run() == nil
}

func (fm *FirewallManager) ruleExists(rule string) bool {
	// 将 -A 替换为 -C 来检查规则是否存在
	checkRule := strings.Replace(rule, "-A ", "-C ", 1)
	cmd := exec.Command("iptables", strings.Fields(checkRule)...)
	return cmd.Run() == nil
}

func (fm *FirewallManager) createChain(chainName string) error {
	return fm.executeIPTables(fmt.Sprintf("-N %s", chainName))
}

func (fm *FirewallManager) deleteChain(chainName string) error {
	// 先清空链
	fm.executeIPTables(fmt.Sprintf("-F %s", chainName))
	// 再删除链
	return fm.executeIPTables(fmt.Sprintf("-X %s", chainName))
}

func (fm *FirewallManager) addRule(chainName, rule string) error {
	fullRule := fmt.Sprintf("-A %s %s", chainName, rule)
	return fm.executeIPTables(fullRule)
}

func (fm *FirewallManager) getChainName(ip string) string {
	// 将IP中的点替换为下划线，避免链名包含特殊字符
	return fm.customChainPrefix + strings.Replace(ip, ".", "_", -1)
}

func (fm *FirewallManager) executeIPTables(rule string) error {
	args := strings.Fields(rule)
	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables command failed: %s, output: %s", err, string(output))
	}
	return nil
}

func (fm *FirewallManager) cleanupUnusedChains(requiredChains map[string]bool) error {
	// 获取所有现有的自定义链
	existingChains := fm.getExistingCustomChains()

	for _, chainName := range existingChains {
		if !requiredChains[chainName] {
			// 清理不需要的链
			if err := fm.deleteChain(chainName); err != nil {
				return fmt.Errorf("failed to delete unused chain %s: %v", chainName, err)
			}
		}
	}

	return nil
}

func (fm *FirewallManager) getExistingCustomChains() []string {
	// 实现获取现有自定义链的逻辑
	// 这里需要解析 iptables -L 的输出
	var chains []string
	// TODO: 实现具体逻辑
	return chains
}

func (fm *FirewallManager) replaceUserChain(userIP, oldChain, newChain string) error {
	// 更新主链中的跳转规则
	rule := fmt.Sprintf("-s %s -j %s", userIP, newChain)

	// 删除旧规则（如果存在）
	oldRule := fmt.Sprintf("-D %s -s %s -j %s", fm.mainChain, userIP, oldChain)
	fm.executeIPTables(oldRule) // 忽略错误，可能规则不存在

	// 添加新规则
	newRule := fmt.Sprintf("-A %s %s", fm.mainChain, rule)
	return fm.executeIPTables(newRule)
}

func (fm *FirewallManager) renameChain(oldName, newName string) error {
	// iptables 不支持重命名，需要通过其他方式实现
	// 这里先保持临时链，下次更新时会被替换
	return nil
}

// Cleanup 清理所有防火墙规则（用于程序退出时）
func (fm *FirewallManager) Cleanup() error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	// 清理所有自定义链
	chains := fm.getExistingCustomChains()
	for _, chain := range chains {
		fm.deleteChain(chain)
	}

	// 清理主链
	if fm.chainExists(fm.mainChain) {
		fm.deleteChain(fm.mainChain)
	}

	return nil
}
