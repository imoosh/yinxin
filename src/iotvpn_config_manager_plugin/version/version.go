package version

import (
	"fmt"
	"runtime"
)

// 通过 -ldflags 注入的变量
var (
	Version = "dev"     // 版本号
	Build   = "unknown" // 构建时间
	GitHash = "unknown" // Git哈希值
)

// BuildInfo 构建信息结构
type BuildInfo struct {
	Version   string `json:"version"`
	Build     string `json:"build"`
	GitHash   string `json:"git_hash"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// GetBuildInfo 获取完整的构建信息
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   Version,
		Build:     Build,
		GitHash:   GitHash,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// GetVersion 获取版本字符串
func GetVersion() string {
	return Version
}

// GetFullVersion 获取完整版本信息字符串
func GetFullVersion() string {
	return fmt.Sprintf("%s-%s (built at %s)", Version, GitHash, Build)
}

// String 实现字符串接口
func (bi BuildInfo) String() string {
	return fmt.Sprintf("Version: %s\nBuild: %s\nGit Hash: %s\nGo Version: %s\nOS/Arch: %s/%s",
		bi.Version, bi.Build, bi.GitHash, bi.GoVersion, bi.OS, bi.Arch)
}
