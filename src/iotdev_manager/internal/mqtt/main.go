package mqtt

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

const (
	// MQTT服务器地址（使用tls协议）
	mqttServer = "tls://test.mosquitto.org:8883"
	// 订阅的主题
	topic = "paho/golang/tls/example"
	// 客户端ID（确保唯一性）
	clientID = "paho-golang-tls-subscriber"
)

func main() {
	// 创建上下文，用于接收中断信号（如Ctrl+C）
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 解析MQTT服务器URL
	u, err := url.Parse(mqttServer)
	if err != nil {
		fmt.Printf("解析服务器URL失败: %v\n", err)
		os.Exit(1)
	}

	// 配置TLS连接
	tlsConfig := &tls.Config{
		// 根据实际情况配置TLS参数
		// 对于测试服务器，可以禁用证书验证（生产环境不建议）
		// InsecureSkipVerify: true,
		
		// 生产环境应指定服务器名称（与证书匹配）
		ServerName: u.Hostname(),
	}

	// 配置MQTT客户端
	cliCfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{u},
		KeepAlive:                     30, // 30秒心跳间隔
		CleanStartOnInitialConnection: false,
		SessionExpiryInterval:         3600, // 会话过期时间（1小时）
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
			fmt.Println("MQTT连接已建立")
			// 连接建立后订阅主题
			if _, err := cm.Subscribe(ctx, &paho.Subscribe{
				Subscriptions: []paho.SubscribeOptions{
					{
						Topic:             topic,
						QoS:               1, // QoS级别1
						NoLocal:           false,
						RetainAsPublished: false,
					},
				},
			}); err != nil {
				fmt.Printf("订阅主题失败: %v\n", err)
			} else {
				fmt.Printf("已订阅主题: %s\n", topic)
			}
		},
		OnConnectError: func(err error) {
			fmt.Printf("连接错误: %v\n", err)
		},
		// 配置TLS连接
		TlsCfg: tlsConfig,
		// 基础MQTT客户端配置
		ClientConfig: paho.ClientConfig{
			ClientID: clientID,
			// 处理接收到的消息
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					fmt.Printf(
						"收到消息 - 主题: %s, 内容: %s, QoS: %d, 保留: %t\n",
						pr.Packet.Topic,
						string(pr.Packet.Payload),
						pr.Packet.QoS,
						pr.Packet.Retain,
					)
					return true, nil // 确认消息处理完成
				},
			},
			OnClientError: func(err error) {
				fmt.Printf("客户端错误: %v\n", err)
			},
			OnServerDisconnect: func(d *paho.Disconnect) {
				if d.Properties != nil {
					fmt.Printf("服务器断开连接: %s\n", d.Properties.ReasonString)
				} else {
					fmt.Printf("服务器断开连接，原因码: %d\n", d.ReasonCode)
				}
			},
		},
	}

	// 创建连接管理器（自动处理重连）
	cm, err := autopaho.NewConnection(ctx, cliCfg)
	if err != nil {
		fmt.Printf("创建连接管理器失败: %v\n", err)
		os.Exit(1)
	}

	// 等待连接成功
	if err = cm.AwaitConnection(ctx); err != nil {
		fmt.Printf("等待连接失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("等待接收消息（按Ctrl+C退出）...")

	// 等待中断信号
	<-ctx.Done()
	fmt.Println("\n收到退出信号，正在关闭连接...")

	// 优雅关闭连接
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cm.Disconnect(ctxShutdown); err != nil {
		fmt.Printf("关闭连接错误: %v\n", err)
	}
	<-cm.Done()
	fmt.Println("退出完成")
}
