package mqtt_msg_handle

//处理mqtt消息

import (
	"fmt"
)

// 处理mqtt消息 总入口
func HandleMessage(topic string, data []byte) error {
	fmt.Println("HandleMessage", topic, string(data))

	msg, err := ParseMessage(topic, data)
	if err != nil {
		return err
	}

	if err := SaveMessage(topic, msg); err != nil {
		return err
	}

	return nil
}
