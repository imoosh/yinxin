package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// StartDaemon 启动守护进程
func StartDaemon() error {
	// 获取当前可执行文件路径
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// 获取当前工作目录
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// 准备命令行参数，移除 -d 标志
	args := []string{}
	for _, arg := range os.Args[1:] {
		if arg != "-d" && arg != "--daemon" {
			args = append(args, arg)
		}
	}

	// 创建新进程
	cmd := exec.Command(executable, args...)
	cmd.Dir = wd

	// 设置进程与父进程分离
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	// 启动进程
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// 输出进程ID
	fmt.Printf("Daemon started with PID: %d\n", cmd.Process.Pid)

	// 将PID写入文件
	pidFile := filepath.Join(wd, "iotdev_manager.pid")
	err = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	if err != nil {
		fmt.Printf("Warning: failed to write PID file: %v\n", err)
	}

	// 父进程退出
	os.Exit(0)
	return nil
}