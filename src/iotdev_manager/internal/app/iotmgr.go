package app

import (
	"context"
	"fmt"
	"iotdev_manager/internal/config"
	"iotdev_manager/internal/logger"
	"iotdev_manager/internal/mqtt"
	"os"
	"os/signal"
	"syscall"
)

// App 应用程序结构
type iotmgrApp struct {
	config config.Config
	logger logger.Logger

	ctx      context.Context
	stopFunc context.CancelFunc
}

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

// Run 运行应用程序
func (a *iotmgrApp) Run() error {
	a.logger.Info("Starting %s version %s on %s",
		a.config.App.Name,
		a.config.App.Version,
		a.config.MQTT.Broker)

	// 这里实现应用程序的主要逻辑
	a.logger.Info("Application is running...")

	sub, err := mqtt.NewMQTTSubscriber(a.ctx, &a.config.MQTT)
	if err != nil {
		return err
	}

	sub.Subscribe(func(data []byte) error {
		fmt.Printf("iotmgrApp 接受消息: %s\n", string(data))

		return nil
	})

	<-a.ctx.Done()

	return nil
}
