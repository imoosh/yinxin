package app

import (
	"iotdev_manager/internal/config"
	"iotdev_manager/internal/logger"
)

// App 应用程序结构
type App struct {
	config *config.Config
	logger logger.Logger
}

// NewApp 创建新的应用实例
func NewApp(config *config.Config, logger logger.Logger) *App {
	return &App{
		config: config,
		logger: logger,
	}
}

// Run 运行应用程序
func (a *App) Run() error {
	a.logger.Info("Starting %s version %s on port %d",
		a.config.App.Name,
		a.config.App.Version,
		a.config.App.Port)

	/*
		// 初始化mqtt连接
		err := mqtt.InitMQTTConnection(a.config.MQTT)
		if err != nil {
			a.logger.Error("Failed to initialize MQTT connection: %v", err)
			return err
		}
		defer mqtt.CloseMQTTConnection()

		// 订阅主题
		err = mqtt.Subscribe(a.config.MQTT.Topic)
		if err != nil {
			a.logger.Error("Failed to subscribe to topic: %v", err)
			return err
		}
	*/
	// 这里实现应用程序的主要逻辑
	a.logger.Info("Application is running...")

	return nil
}
