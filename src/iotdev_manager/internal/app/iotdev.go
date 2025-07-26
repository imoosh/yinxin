package app

import (
	"context"
	"iotdev_manager/internal/config"
	"iotdev_manager/internal/logger"
	"os"
	"os/signal"
	"syscall"
)

// NewPubApp 创建新的应用实例
func NewIotdevApp(config config.Config, logger logger.Logger) *PubApp {
	// 创建上下文，用于接收中断信号（如Ctrl+C）
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	config.App.Name = "iotdev"
	config.MQTT.ClientID = "iotdev-mocker"
	return &PubApp{
		config:   config,
		logger:   logger,
		ctx:      ctx,
		stopFunc: stop,
	}
}
