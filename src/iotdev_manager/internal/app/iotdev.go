package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"iotdev_manager/internal/config"
	"iotdev_manager/internal/logger"
	"iotdev_manager/internal/mqtt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// PubApp 应用程序结构
type iotdevApp struct {
	config config.Config
	logger logger.Logger

	ctx      context.Context
	stopFunc context.CancelFunc
}

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

func (a *iotdevApp) Stop() {
	if a.stopFunc != nil {
		a.stopFunc()
	}
}

// Run 运行应用程序
func (a *iotdevApp) Run() error {
	var err error
	a.logger.Info("Starting %s version %s on %s",
		a.config.App.Name,
		a.config.App.Version,
		a.config.MQTT.Broker)

	// 这里实现应用程序的主要逻辑
	a.logger.Info("Application is running...")

	pub, err := mqtt.NewMQTTPublisher(a.ctx, &a.config.MQTT)
	if err != nil {
		return err
	}

	go func() {
		for {
			<-a.ctx.Done()
			if err := a.ctx.Err(); err != nil {
				fmt.Println("publish: Aborting due to: ", err)
				os.Exit(1)
			}
		}
	}()

	time.Sleep(time.Second)
	stdin := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-a.ctx.Done():
		default:
		}

		fmt.Printf("\nInput> ")
		message, err := stdin.ReadString('\n')
		if err == io.EOF {
			break
		}
		message = strings.TrimRight(message, "\n")

		fmt.Printf("发送消息: %v\n", message)
		if err := pub.Publish([]byte(message)); err != nil {
			fmt.Println("error sending message:", err)
			continue
		}
	}
	return err
}
