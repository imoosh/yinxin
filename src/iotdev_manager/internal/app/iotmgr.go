package app

import (
	"context"
	"iotdev_manager/internal/config"
	"iotdev_manager/internal/logger"
	"os"
	"os/signal"
	"syscall"
)
// NewSubApp 创建新的应用实例
func NewIotmgrApp(config config.Config, logger logger.Logger) *SubApp {
	// 创建上下文，用于接收中断信号（如Ctrl+C）
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	return &SubApp{
		config:   config,
		logger:   logger,
		ctx:      ctx,
		stopFunc: stop,
	}
}
