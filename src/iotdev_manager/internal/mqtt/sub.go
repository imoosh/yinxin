package mqtt

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"

	"iotdev_manager/internal/config"
)

// https://github.com/eclipse-paho/paho.golang/blob/master/autopaho/examples/queue/subscribe.go

type SubscribeHandler func(string, []byte) error

type MQTTSubscriber struct {
	cfg config.MQTTConfig
	cm  *autopaho.ConnectionManager

	serverURL      *url.URL
	ctx            context.Context
	useMemoryQueue bool
	queuex         queueWaitForEmpty

	lastMsgTime time.Time

	packetChan chan *paho.Publish
}

func NewMQTTSubscriber(ctx context.Context, cfg *config.MQTTConfig) (*MQTTSubscriber, error) {
	var err error

	sub := new(MQTTSubscriber)
	sub.cfg = *cfg
	sub.ctx = ctx
	sub.useMemoryQueue = true
	sub.lastMsgTime = time.Now()
	sub.packetChan = make(chan *paho.Publish)

	serverURL, err := url.Parse(cfg.Broker)
	if err != nil {
		fmt.Printf("解析服务器URL失败: %v\n", err)
		return nil, err
	}
	sub.serverURL = serverURL

	cm, err := sub.Connection()
	if err != nil {
		fmt.Printf("创建mqtt连接失败: %v\n", err)
		return nil, err
	}
	sub.cm = cm

	return sub, nil
}

func (sub *MQTTSubscriber) Connection() (*autopaho.ConnectionManager, error) {

	tlsCfg, err := tlsConfig(&sub.cfg)
	if err != nil {
		fmt.Printf("init tls config failed: %v\n", err)
		return nil, err
	}

	cliCfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{sub.serverURL},
		TlsCfg:                        tlsCfg,
		KeepAlive:                     20,   // Keepalive message should be sent every 20 seconds
		CleanStartOnInitialConnection: true, // Previous tests should not contaminate this one!
		SessionExpiryInterval:         60,   // If connection drops we want session to remain live whilst we reconnect
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
			fmt.Println("mqtt connection up")
			if _, err := cm.Subscribe(sub.ctx, &paho.Subscribe{
				Subscriptions: sub.cfg.Subs,
			}); err != nil {
				fmt.Printf("subscribe: failed to subscribe (%s). Probably due to connection drop so will retry\n", err)
				return // likely connection has dropped
			}
			fmt.Println("subscribe: mqtt subscription made")
		},
		OnConnectError: func(err error) { fmt.Printf("subscribe: error whilst attempting connection: %s\n", err) },
		Errors:         logger{prefix: "subscribe"},

		// eclipse/paho.golang/paho provides base mqtt functionality, the below config will be passed in for each connection
		ClientConfig: paho.ClientConfig{
			ClientID: sub.cfg.ClientID,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					sub.packetChan <- pr.Packet
					return true, nil
				}},
			OnClientError: func(err error) { fmt.Printf("subscribe: client error: %s\n", err) },
			OnServerDisconnect: func(d *paho.Disconnect) {
				if d.Properties != nil {
					fmt.Printf("subscribe: server requested disconnect: %s\n", d.Properties.ReasonString)
				} else {
					fmt.Printf("subscribe:server requested disconnect; reason code: %d\n", d.ReasonCode)
				}
			},
		},
	}

	c, err := autopaho.NewConnection(sub.ctx, cliCfg)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// 打印数据的十六进制表示，左侧为十六进制值，右侧为可见字符
func PrintHex(data []byte) {
	if len(data) == 0 {
		return
	}

	// 每行显示16个字节
	lineSize := 16

	// 计算总共有多少行
	lines := (len(data) + lineSize - 1) / lineSize

	for i := 0; i < lines; i++ {
		// 计算当前行的起始和结束索引
		start := i * lineSize
		end := start + lineSize
		if end > len(data) {
			end = len(data)
		}
		currentLineLength := end - start

		// 打印偏移量（十六进制，8位）
		fmt.Printf("%08x  ", start)

		// 打印十六进制数据
		hexCount := 0
		for j := start; j < end; j++ {
			fmt.Printf("%02x ", data[j])
			hexCount++
			
			// 每8个字节后添加一个额外空格，增强可读性
			if (j-start+1)%8 == 0 && j != end-1 {
				fmt.Print(" ")
				hexCount++ // 记录额外添加的空格
			}
		}

		// 计算需要填充的空格数，确保右侧字符区对齐
		// 满行16字节时，十六进制区域应有16*3 + 1 = 49个字符(包含中间空格)
		// 前8字节后有一个额外空格
		fullLineHexLength := 16*3 + 1 // 16个字节*3字符/字节 + 1个中间空格
		currentHexLength := currentLineLength*3
		if currentLineLength > 8 {
			currentHexLength += 1 // 超过8字节时添加的中间空格
		}
		spacesToAdd := fullLineHexLength - currentHexLength
		for k := 0; k < spacesToAdd; k++ {
			fmt.Print(" ")
		}

		// 添加分隔符
		fmt.Print(" | ")

		// 打印对应的可见字符
		for j := start; j < end; j++ {
			b := data[j]
			// 32-126是可打印ASCII字符
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				// 不可见字符用.表示
				fmt.Print(".")
			}
		}

		fmt.Println()
	}
}

func (sub *MQTTSubscriber) Subscribe(fn SubscribeHandler) error {
	var err error

waitLoop:
	for {
		select {
		case <-sub.ctx.Done():
			err = sub.ctx.Err()
			break waitLoop
		case pack := <-sub.packetChan:
			fmt.Printf("Received Raw: topic: %s, payload: \n", pack.Topic)
            PrintHex(pack.Payload)
			if fn != nil {
				fn(pack.Topic, pack.Payload)
			}
		}
	}

	if err != nil {
		fmt.Println("subscribe: Aborting due to: ", err)
		return nil
	}

	fmt.Println("subscribe: All received, disconnecting")
	if err = sub.cm.Disconnect(context.Background()); err != nil {
		return err
	}
	<-sub.cm.Done()
	fmt.Println("subscribe: Done")

	return nil
}
