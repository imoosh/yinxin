package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"iotdev_manager/internal/app"
	"iotdev_manager/internal/config"
	"iotdev_manager/internal/daemon"
	"iotdev_manager/internal/logger"
)

var (
	configPath string
	daemonMode bool
)

func main() {
	// 创建根命令
	rootCmd := &cobra.Command{
		Use:   "iotmgr",
		Short: "iotmgr - 一个iot终端设备mqtt订阅程序",
		Long:  `iotmgr 是一个iot终端设备mqtt订阅程序，处理订阅事件`,
		Run: func(cmd *cobra.Command, args []string) {
			// 检查配置文件路径
			if configPath == "" {
				configPath = "etc/iotmgr.yaml"
			}

			// 加载配置
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				log.Fatalf("Failed to load configuration: %v", err)
			}

			// 初始化日志
			logger := logger.NewLogger(cfg.Log)
			logger.Info("Application starting...")
            logger.Info("using config: %s", configPath)
            cfg.Print(logger.Info)

			// 如果是后台运行模式
			if daemonMode {
				logger.Info("Starting daemon mode...")
				err := daemon.StartDaemon()
				if err != nil {
					logger.Error("Failed to start daemon: %v", err)
					os.Exit(1)
				}
				// StartDaemon 成功后会自动退出父进程
			}

			// 初始化应用
			application := app.NewIotmgrApp(*cfg, logger)

			// 运行应用
			if err := application.Run(); err != nil {
				logger.Error("Application failed to run: %v", err)
			}

			logger.Info("Application shutdown complete")
		},
	}

	// 添加命令行参数
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "", "配置文件路径 (默认为 etc/iotmgr.yaml)")
	rootCmd.Flags().BoolVarP(&daemonMode, "daemon", "d", false, "以后台模式运行")

	// 执行命令
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
