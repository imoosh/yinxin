package api

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"iotvpn_config_manager_plugin/sslvpn/pkg/types"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FirewallManager 使用“影子链”方案管理防火墙规则
type FirewallManager struct {
	baseChainPrefix string // e.g., "iv" for iot-vpn
	tunInterface    string
	mutex           sync.Mutex
	initialized     bool
}

// NewFirewallManager 创建防火墙管理器
func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		baseChainPrefix: "iv", // 使用缩写以节省空间
		tunInterface:    "tun0",
	}
}

// Initialize 确保iptables中存在一个基础跳转规则到我们的管理链
func (fm *FirewallManager) Initialize() error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	return fm.initializeInternal()
}

// AdjustFirewall 使用影子链方案更新防火墙规则
func (fm *FirewallManager) AdjustFirewall(authorities *types.AuthoRuleGet) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if err := fm.initializeInternal(); err != nil {
		return fmt.Errorf("failed to initialize firewall: %v", err)
	}

	// 如果禁用访问控制，则清理规则
	if !authorities.Enable {
		fmt.Println("Access control is disabled. Cleaning up firewall rules...")
		return fm.cleanupInternal()
	}

	// 1. 生成新版本号并创建新版本的链
	newVersion := fm.generateNewVersion()
	mainChainV2 := fm.getVersionedChainName(newVersion)
	userChainsV2 := make(map[string]string)

	fmt.Printf("Step 1: Building new rule set with version %s\n", newVersion)
	if err := fm.createChain(mainChainV2); err != nil {
		return fmt.Errorf("failed to create new main chain %s: %v", mainChainV2, err)
	}

	for _, auth := range authorities.Auth {
		if auth.User.Enable && auth.User.BindIP != "" {
			userChainV2 := fm.getVersionedUserChainName(auth.User.CertCN, newVersion)
			userChainsV2[auth.User.BindIP] = userChainV2

			// 创建并填充用户链
			if err := fm.buildUserChain(userChainV2, &auth); err != nil {
				fm.cleanupVersion(newVersion) // 出错时清理新版本
				return err
			}

			// 在新主链中添加跳转规则
			jumpRule := fmt.Sprintf("-A %s -s %s -j %s", mainChainV2, auth.User.BindIP, userChainV2)
			if err := fm.executeIPTables(jumpRule); err != nil {
				fm.cleanupVersion(newVersion) // 出错时清理新版本
				return err
			}
		}
	}

	// 2. 原子性切换或创建
	fmt.Printf("Step 2: Atomically switching or creating jump rule\n")
	ruleNum, err := fm.findCurrentVersionChain("FORWARD", fm.baseChainPrefix)

	if err != nil {
		// 如果规则不存在，说明是首次创建或规则被外部删除，我们添加它
		fmt.Printf("Jump rule not found in FORWARD chain, creating a new one.\n")
		jumpRule := fmt.Sprintf("-A FORWARD -i %s -m state --state NEW -j %s", fm.tunInterface, mainChainV2)
		if err := fm.executeIPTables(jumpRule); err != nil {
			fm.cleanupVersion(newVersion) // 出错时清理新版本
			return fmt.Errorf("failed to create new jump rule: %v", err)
		}
	} else {
		// 如果规则存在，我们原子性地替换它
		fmt.Printf("Found existing jump rule at index %d, replacing it.\n", ruleNum)
		replaceRule := fmt.Sprintf("-R FORWARD %d -i %s -m state --state NEW -j %s", ruleNum, fm.tunInterface, mainChainV2)
		if err := fm.executeIPTables(replaceRule); err != nil {
			fm.cleanupVersion(newVersion) // 出错时清理新版本
			return fmt.Errorf("atomic switch failed: %v", err)
		}
	}

	// 3. 清理旧版本
	fmt.Printf("Step 3: Cleaning up old rule sets\n")
	fm.cleanupOldVersions(newVersion)

	fmt.Println("Firewall rules updated successfully.")
	return nil
}

// Cleanup 移除所有由本程序创建的防火墙规则
func (fm *FirewallManager) Cleanup() error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	return fm.cleanupInternal()
}

// --- 内部不加锁方法 ---

// initializeInternal 执行实际的初始化逻辑，假定调用者已持有锁
func (fm *FirewallManager) initializeInternal() error {
	if fm.initialized {
		return nil
	}

	// 确保 RELATED,ESTABLISHED 流量被接受
	establishedRule := "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
	if !fm.ruleExists(establishedRule) {
		if err := fm.executeIPTables(establishedRule); err != nil {
			return fmt.Errorf("failed to add established rule: %v", err)
		}
	}

	// 如果还没有任何版本的管理链，创建一个空的初始版本
	if _, err := fm.findCurrentVersionChain("FORWARD", fm.baseChainPrefix); err != nil {
		initialVersion := fm.generateNewVersion()
		initialChain := fm.getVersionedChainName(initialVersion)
		if err := fm.createChain(initialChain); err != nil {
			return fmt.Errorf("failed to create initial chain %s: %v", initialChain, err)
		}

		jumpRule := fmt.Sprintf("-A FORWARD -i %s -m state --state NEW -j %s", fm.tunInterface, initialChain)
		if err := fm.executeIPTables(jumpRule); err != nil {
			return fmt.Errorf("failed to add initial jump rule: %v", err)
		}
	}

	fm.initialized = true
	return nil
}

// cleanupInternal 执行实际的清理逻辑，假定调用者已持有锁
func (fm *FirewallManager) cleanupInternal() error {
	fmt.Println("Cleaning up all firewall rules created by this manager...")

	// 找到并删除 FORWARD 链中的跳转规则
	ruleNum, err := fm.findCurrentVersionChain("FORWARD", fm.baseChainPrefix)
	if err == nil {
		deleteRule := fmt.Sprintf("-D FORWARD %d", ruleNum)
		if err := fm.executeIPTables(deleteRule); err != nil {
			fmt.Printf("Warning: failed to delete jump rule from FORWARD chain: %v\n", err)
		}
	}

	// 清理所有版本的链
	fm.cleanupOldVersions("") // 传入""表示删除所有版本

	return nil
}

// --- 辅助方法 ---

func (fm *FirewallManager) buildUserChain(chainName string, auth *types.AuthRuleVerboseOne) error {
	if err := fm.createChain(chainName); err != nil {
		return err
	}

	// 允许 DNS
	dnsRule := fmt.Sprintf("-A %s -p udp --dport 53 -j ACCEPT", chainName)
	if err := fm.executeIPTables(dnsRule); err != nil {
		return err
	}

	// 添加资源规则
	for _, res := range auth.Resources {
		if res.Enable {
			resRule := fmt.Sprintf("-A %s -d %s -j ACCEPT", chainName, res.IP)
			if err := fm.executeIPTables(resRule); err != nil {
				return err
			}
		}
	}

	// 默认拒绝
	dropRule := fmt.Sprintf("-A %s -j DROP", chainName)
	return fm.executeIPTables(dropRule)
}

func (fm *FirewallManager) findCurrentVersionChain(chain, prefix string) (int, error) {
	cmd := exec.Command("iptables", "-L", chain, "--line-numbers", "-n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("failed to list chain %s: %v", chain, err)
	}

	lines := strings.Split(string(output), "\n")
	re := regexp.MustCompile(fmt.Sprintf(`^(\d+)\s+.*\s+%s-[0-9a-f]{6}$`, prefix))

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 2 {
			num, _ := strconv.Atoi(matches[1])
			return num, nil
		}
	}
	return 0, fmt.Errorf("no rule found in chain %s with prefix %s", chain, prefix)
}

func (fm *FirewallManager) cleanupOldVersions(keepVersion string) {
	fmt.Printf("Starting cleanup of old versions (keeping version: %s)\n", keepVersion)

	// --- 清理 FORWARD 链中的无效跳转规则 ---
	cmd := exec.Command("iptables", "-S", "FORWARD")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: Failed to list FORWARD chain rules for cleanup: %v\n", err)
		return // 如果无法获取规则，则跳过清理
	}

	lines := strings.Split(string(output), "\n")
	re := regexp.MustCompile(fmt.Sprintf(`-j %s-([0-9a-f]{6})`, fm.baseChainPrefix))

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 2 {
			version := matches[1]
			// 如果版本不是需要保留的当前版本，则删除这条跳转规则
			if keepVersion == "" || version != keepVersion {
				deleteRule := strings.Replace(line, "-A", "-D", 1)
				if err := fm.executeIPTables(deleteRule); err != nil {
					fmt.Printf("Warning: Failed to delete old jump rule from FORWARD chain: %v\n", err)
				} else {
					fmt.Printf("Successfully deleted old jump rule pointing to version %s from FORWARD chain\n", version)
				}
			}
		}
	}

	// --- 获取所有现有链的列表 ---
	cmd = exec.Command("iptables", "-L", "-n")
	output, _ = cmd.CombinedOutput()
	lines = strings.Split(string(output), "\n")

	// 收集所有需要清理的版本
	versionsToCleanup := make(map[string]bool)

	// 查找主链
	mainChainRe := regexp.MustCompile(fmt.Sprintf(`^Chain %s-([0-9a-f]{6})$`, fm.baseChainPrefix))
	for _, line := range lines {
		matches := mainChainRe.FindStringSubmatch(line)
		if len(matches) == 2 {
			version := matches[1]
			if keepVersion == "" || version != keepVersion {
				versionsToCleanup[version] = true
			}
		}
	}

	// 查找用户链（可能包含不同格式的链名）
	userChainRe := regexp.MustCompile(`^Chain (u-.+-([0-9a-f]{6}))\s+`)
	for _, line := range lines {
		matches := userChainRe.FindStringSubmatch(line)
		if len(matches) >= 3 {
			version := matches[2]
			if keepVersion == "" || version != keepVersion {
				versionsToCleanup[version] = true
			}
		}
	}

	// 清理所有发现的旧版本
	for version := range versionsToCleanup {
		fmt.Printf("Cleaning up old version: %s\n", version)
		fm.cleanupVersion(version)
	}

	fmt.Printf("Cleanup completed. Total versions cleaned: %d\n", len(versionsToCleanup))
}

func (fm *FirewallManager) cleanupVersion(version string) {
	// 删除所有与此版本相关的链
	mainChain := fm.getVersionedChainName(version)

	// 1. 先清空主链，这会移除对所有用户子链的引用
	if err := fm.executeIPTables(fmt.Sprintf("-F %s", mainChain)); err != nil {
		fmt.Printf("Warning: failed to flush old main chain %s during cleanup: %v\n", mainChain, err)
	}

	// 2. 查找并删除此版本的所有用户链
	cmd := exec.Command("iptables", "-L", "-n")
	output, _ := cmd.CombinedOutput()
	lines := strings.Split(string(output), "\n")

	// 更精确的正则表达式匹配用户链，使用版本号作为后缀
	// 格式: "Chain u-<任意字符>-<版本号>"
	versionEscaped := regexp.QuoteMeta(version)
	re := regexp.MustCompile(fmt.Sprintf(`^Chain (u-.+-%s)\s+`, versionEscaped))

	userChainsToDelete := []string{}
	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			userChain := matches[1]
			userChainsToDelete = append(userChainsToDelete, userChain)
		}
	}

	// 删除找到的用户链
	for _, userChain := range userChainsToDelete {
		if err := fm.deleteChain(userChain); err != nil {
			fmt.Printf("Warning: failed to delete old user chain %s: %v\n", userChain, err)
		} else {
			fmt.Printf("Successfully deleted old user chain %s\n", userChain)
		}
	}

	// 3. 最后删除（现在为空的）主链
	if err := fm.deleteChain(mainChain); err != nil {
		fmt.Printf("Warning: failed to delete old main chain %s: %v\n", mainChain, err)
	} else {
		fmt.Printf("Successfully deleted old main chain %s\n", mainChain)
	}
}

func (fm *FirewallManager) getVersionedChainName(version string) string {
	return fmt.Sprintf("%s-%s", fm.baseChainPrefix, version)
}

func (fm *FirewallManager) getVersionedUserChainName(userCN string, version string) string {
	// iptables链名最大长度为28字符，我们需要为"u-"预留2字符，为"-"预留1字符
	// 因此CN部分+版本部分最多25字符
	maxTotalLength := 25

	// 将版本限制为6字符（已经在generateNewVersion中处理）
	versionPart := version
	if len(versionPart) > 10 {
		versionPart = versionPart[:10]
	}

	// CN部分的最大长度 = 总长度 - 版本长度 - 1（连接符）
	maxCNLength := maxTotalLength - len(versionPart) - 1

	// 处理UTF-8字符串，确保不会截断多字节字符
	cnPart := userCN
	if len([]rune(cnPart)) > maxCNLength {
		// 转换为rune切片来正确处理Unicode字符
		runes := []rune(cnPart)
		if len(runes) > maxCNLength {
			runes = runes[:maxCNLength]
		}
		cnPart = string(runes)
	}

	// 确保最终字符串的字节长度不超过限制
	chainName := fmt.Sprintf("u-%s-%s", cnPart, versionPart)
	if len(chainName) > 28 {
		// 如果仍然超长，进一步缩短CN部分
		excess := len(chainName) - 28
		if len([]rune(cnPart)) > excess {
			runes := []rune(cnPart)
			runes = runes[:len(runes)-excess]
			cnPart = string(runes)
			chainName = fmt.Sprintf("u-%s-%s", cnPart, versionPart)
		}
	}

	return chainName
}

// generateNewVersion 生成一个短的、唯一的版本标识符
func (fm *FirewallManager) generateNewVersion() string {
	// 使用时间戳的纳秒部分并进行哈希，取前6位
	hasher := md5.New()
	hasher.Write([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	return hex.EncodeToString(hasher.Sum(nil))[:6]
}

func (fm *FirewallManager) createChain(chainName string) error {
	return fm.executeIPTables(fmt.Sprintf("-N %s", chainName))
}

func (fm *FirewallManager) deleteChain(chainName string) error {
	// 确保链存在才操作
	if !fm.chainExists(chainName) {
		return nil
	}

	// 清空链
	if err := fm.executeIPTables(fmt.Sprintf("-F %s", chainName)); err != nil {
		// 忽略 "No chain" 错误，因为它可能在并发操作中被删除
		if !strings.Contains(err.Error(), "No chain/target/match by that name") {
			return fmt.Errorf("failed to flush chain %s: %v", chainName, err)
		}
	}
	// 删除链
	if err := fm.executeIPTables(fmt.Sprintf("-X %s", chainName)); err != nil {
		if !strings.Contains(err.Error(), "No chain/target/match by that name") {
			return fmt.Errorf("failed to delete chain %s: %v", chainName, err)
		}
	}
	return nil
}

func (fm *FirewallManager) chainExists(chainName string) bool {
	cmd := exec.Command("iptables", "-S", chainName)
	// .Run() will return a non-nil error if the chain does not exist (non-zero exit code).
	// We can ignore the output, we only care about the exit status.
	return cmd.Run() == nil
}

func (fm *FirewallManager) ruleExists(rule string) bool {
	checkRule := strings.Replace(rule, "-A", "-C", 1)
	cmd := exec.Command("iptables", strings.Fields(checkRule)...)
	return cmd.Run() == nil
}

func (fm *FirewallManager) executeIPTables(rule string) error {
	args := strings.Fields(rule)
	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables command '%s' failed: %s, output: %s", rule, err, string(output))
	}
	return nil
}
