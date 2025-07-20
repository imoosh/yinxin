package mqtt

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/autopaho/queue"
	"github.com/eclipse/paho.golang/autopaho/queue/file"
	"github.com/eclipse/paho.golang/autopaho/queue/memory"
	"github.com/eclipse/paho.golang/paho"

	"iotdev_manager/internal/config"
)

// https://github.com/eclipse-paho/paho.golang/blob/master/autopaho/examples/queue/publish.go

type MQTTPublisher struct {
	cfg config.MQTTConfig
	ctx context.Context

	serverURL      *url.URL
	useMemoryQueue bool
	queuex         queueWaitForEmpty

	cm *autopaho.ConnectionManager
}

func NewMQTTPublisher(ctx context.Context, cfg *config.MQTTConfig) (*MQTTPublisher, error) {
	var err error
	pub := new(MQTTPublisher)
	pub.cfg = *cfg
	pub.ctx = ctx
	pub.useMemoryQueue = true

	serverURL, err := url.Parse(cfg.Broker)
	if err != nil {
		fmt.Printf("解析服务器URL失败: %v\n", err)
		return nil, err
	}
	pub.serverURL = serverURL

	cm, err := pub.Connection()
	if err != nil {
		fmt.Printf("创建mqtt连接失败: %v\n", err)
		return nil, err
	}
	pub.cm = cm

	return pub, nil
}

type queueWaitForEmpty interface {
	queue.Queue
	WaitForEmpty() chan struct{}
}

func (pub *MQTTPublisher) Disconnect() {
	if pub.cm != nil {
		pub.cm.Disconnect(pub.ctx)
	}
	// <-p.ctx.Done()
	// fmt.Println("publish: Context cancelled")
	// <-p.cm.Done()
	// fmt.Println("publish: Clean Shutdown")
}

func (pub *MQTTPublisher) Connection() (*autopaho.ConnectionManager, error) {

	var err error
	if pub.useMemoryQueue {
		pub.queuex = memory.New()
	} else {
		// Store queue files in the current folder (a bit messy but makes it obvious if any files are left behind)
		pub.queuex, err = file.New("./", "queue", ".msg")
		if err != nil {
			return nil, err
		}
	}

	// Previous runs of the test may have left messages queued; remove them!
	for {
		entry, err := pub.queuex.Peek()
		if errors.Is(err, queue.ErrEmpty) {
			break
		}
		if err == nil {
			err = entry.Remove()
		}
		if err != nil {
			return nil, err
		}
	}

	tlsCfg, err := tlsConfig(&pub.cfg)
	if err != nil {
		fmt.Printf("init tls config failed: %v\n", err)
		return nil, err
	}

	cliCfg := autopaho.ClientConfig{
		Queue:                         pub.queuex,
		ServerUrls:                    []*url.URL{pub.serverURL},
		TlsCfg:                        tlsCfg,
		KeepAlive:                     20,   // Keepalive message should be sent every 20 seconds
		CleanStartOnInitialConnection: true, // Previous tests should not contaminate this one!
		SessionExpiryInterval:         60,   // If connection drops we want session to remain live whilst we reconnect
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
			fmt.Println("publish: mqtt connection up")
		},
		OnConnectError: func(err error) { fmt.Printf("publish: error whilst attempting connection: %s\n", err) },
		Errors:         logger{prefix: "publish"},
		// Debug:          logger{prefix: "publish: debug"},
		PahoErrors: logger{prefix: "publishP"},
		// PahoDebug:      logger{prefix: "publishP: debug"},
		// eclipse/paho.golang/paho provides base mqtt functionality, the below config will be passed in for each connection
		ClientConfig: paho.ClientConfig{
			ClientID:      pub.cfg.ClientID,
			OnClientError: func(err error) { fmt.Printf("publish: client error: %s\n", err) },
			OnServerDisconnect: func(d *paho.Disconnect) {
				if d.Properties != nil {
					fmt.Printf("publish: server requested disconnect: %s\n", d.Properties.ReasonString)
				} else {
					fmt.Printf("publish:server requested disconnect; reason code: %d\n", d.ReasonCode)
				}
			},
		},
	}

	c, err := autopaho.NewConnection(pub.ctx, cliCfg)
	if err != nil {
		return c, err
	}

	return c, nil
}

func (pub *MQTTPublisher) Publish(data []byte) error {
	err := pub.cm.PublishViaQueue(pub.ctx, &autopaho.QueuePublish{
		Publish: &paho.Publish{
			QoS:     pub.cfg.QoS,
			Topic:   pub.cfg.Topic,
			Payload: data,
		}})
	if err != nil {
		return err
	}
	if pub.ctx.Err() != nil {
		fmt.Println("publish: Aborting due to context")
		return err
	}

	fmt.Println("publish: Messages queued")
	pub.queuex.WaitForEmpty()
	fmt.Println("publish: Messages all sent or inflight")

	return nil
}
