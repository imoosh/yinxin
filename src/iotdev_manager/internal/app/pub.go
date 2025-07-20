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
type PubApp struct {
	config config.Config
	logger logger.Logger

	ctx      context.Context
	stopFunc context.CancelFunc
}

// NewPubApp 创建新的应用实例
func NewPubApp(config config.Config, logger logger.Logger) *PubApp {
	// 创建上下文，用于接收中断信号（如Ctrl+C）
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	config.App.Name = "pubapp"
	config.MQTT.ClientID = "pubapp"
	return &PubApp{
		config:   config,
		logger:   logger,
		ctx:      ctx,
		stopFunc: stop,
	}
}

func (a *PubApp) Stop() {
	if a.stopFunc != nil {
		a.stopFunc()
	}
}

// Run 运行应用程序
func (a *PubApp) Run() error {
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

	/*
		for {
			message, err := readWithContext(a.ctx)
			if err != nil {
				fmt.Println("publish: Aborting due to: ", err)
				break
			}

			if err := pub.Publish([]byte(message)); err != nil {
				fmt.Println("error sending message:", err)
				continue
			}
		}
	*/

	return err
}

func readWithContext(ctx context.Context) (string, error) {
	// 创建管道作为中间缓冲
	reader, writer, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("创建管道失败: %v", err)
	}
	defer reader.Close()

	// 启动协程将标准输入复制到管道
	go func() {
		// 当上下文取消时关闭写入端，触发reader的EOF
		go func() {
			<-ctx.Done()
			writer.Close()
		}()

		// 将标准输入复制到管道
		bufio.NewReader(os.Stdin).WriteTo(writer)
	}()

	// 从管道读取（而非直接从os.Stdin）
	scanner := bufio.NewScanner(reader)
	if scanner.Scan() {
		return scanner.Text(), nil
	}

	// 检查错误：优先返回上下文错误
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// 其他错误（如管道关闭）
	return "", scanner.Err()
}
