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

type SubscribeHandler func([]byte) error

type MQTTSubscriber struct {
	cfg config.MQTTConfig
	cm  *autopaho.ConnectionManager

	serverURL      *url.URL
	ctx            context.Context
	useMemoryQueue bool
	queuex         queueWaitForEmpty

	lastMsgTime time.Time

	msgChan chan []byte
}

func NewMQTTSubscriber(ctx context.Context, cfg *config.MQTTConfig) (*MQTTSubscriber, error) {
	var err error

	sub := new(MQTTSubscriber)
	sub.cfg = *cfg
	sub.ctx = ctx
	sub.useMemoryQueue = true
	sub.lastMsgTime = time.Now()
	sub.msgChan = make(chan []byte)

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
				Subscriptions: []paho.SubscribeOptions{
					{Topic: sub.cfg.Topic, QoS: sub.cfg.QoS},
				},
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
					message := pr.Packet.Payload
					sub.msgChan <- message
					// fmt.Printf("subscribe: received message: %s\n", string(message))
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

func (sub *MQTTSubscriber) Subscribe(fn SubscribeHandler) error {
	var err error

waitLoop:
	for {
		select {
		case <-sub.ctx.Done():
			err = sub.ctx.Err()
			break waitLoop
		case data:= <-sub.msgChan:
			fmt.Printf("Received Raw: %v\n", data)
			if fn != nil {
				fn(data)
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
