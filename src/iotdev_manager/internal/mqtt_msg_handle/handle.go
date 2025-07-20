package mqtt_msg_handle

//处理mqtt消息

import (
	"fmt"
)

// 处理mqtt消息 总入口
func HandleMessage(topic string, data []byte) error {
	fmt.Printf("HandleMessage: topic: %s data: %s\n", topic, string(data))

	msg, err := ParseMessage(topic, data)
	if err != nil {
		fmt.Printf("HandleMessage: ParseMessage failed: %v\n", err)
		return err
	}

	if err := SaveMessage(topic, msg); err != nil {
		fmt.Printf("HandleMessage: SaveMessage failed: %v\n", err)
		return err
	}

	return nil
}
