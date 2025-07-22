package app

import (
	"context"
	"fmt"
	"iotdev_manager/internal/config"
	"iotdev_manager/internal/logger"
	"iotdev_manager/internal/mqtt"
	"iotdev_manager/internal/mqtt_msg_handle"
	"os"
	"os/signal"
	"syscall"
)

// App 应用程序结构
type SubApp struct {
	config config.Config
	logger logger.Logger

	ctx      context.Context
	stopFunc context.CancelFunc
}

// NewSubApp 创建新的应用实例
func NewSubApp(config config.Config, logger logger.Logger) *SubApp {
	// 创建上下文，用于接收中断信号（如Ctrl+C）
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	config.App.Name = "subapp"
	config.MQTT.ClientID = "subapp"
	return &SubApp{
		config:   config,
		logger:   logger,
		ctx:      ctx,
		stopFunc: stop,
	}
}

// Run 运行应用程序
func (a *SubApp) Run() error {
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

	sub.Subscribe(func(topic string, data []byte) error {
        fmt.Printf("SubApp 接受消息: topic: %s, %s\n", topic, string(data))
		mqtt_msg_handle.HandleMessage(mqtt_msg_handle.TopicRegist, data)
		return nil
	})

	<-a.ctx.Done()

	return nil
}
