package mqtt_msg_handle

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// 创建一个二进制格式的注册消息
func createRegistMessageBytes(deviceID uint16) []byte {
	msg := RegistMessage{
		DeviceID:            deviceID,
		BaudRate:            9600,
		WordLength:          8,
		StopBits:            1,
		Parity:              0,
		Mode:                0,
		HwFlowCtl:           0,
		OverSampling:        0,
		ComProtocol:         COM_RS232,
		MqttProtocolVersion: 4,
		KeepAliveInterval:   60,
		CleanSession:        1,
		WillFlag:            0,
		ServerPort:          1883,
		NetProtocol:         1,
		CaCertLen:           0,
		ClientCertLen:       0,
		KeyUpdateTime:       0,
		AuthType:            AUTH_TYPE_CERT,
		CollectCycle:        5000,
		Timestamp:           1625097600,
	}

	// 设置字符串字段
	copy(msg.DeviceIP[:], []byte("192.168.1.101"))
	copy(msg.DeviceMaskAddr[:], []byte("255.255.255.0"))
	copy(msg.DeviceGwAddr[:], []byte("192.168.1.1"))
	copy(msg.MqClientID[:], []byte("testClient"))
	copy(msg.MqDeviceName[:], []byte("testDevice"))
	copy(msg.MqDevicePassword[:], []byte("testPwd"))
	copy(msg.ServerIP[:], []byte("192.168.1.200"))
	copy(msg.CollectItem[:], []byte("pressure"))
	copy(msg.CollectTopic[:], []byte("pressure"))

	msg.ClientCertLen = 860
	certData, _ := base64.StdEncoding.DecodeString("MIIDWDCCAkCgAwIBAgIIBhzn6HQDWJQwDQYJKoZIhvcNAQELBQAwTjELMAkGA1UEBhMCYWExCzAJBgNVBAgTAmFhMQswCQYDVQQHEwJhYTELMAkGA1UEChMCYWExCzAJBgNVBAsTAmFhMQswCQYDVQQDEwJhYTAeFw0yNTA3MTkwMjAzMDBaFw0yNjA3MTkwMjAzMDBaMIGJMQswCQYDVQQGEwJhYTELMAkGA1UECBMCYmIxCzAJBgNVBAcTAmNjMQswCQYDVQQKEwJkZDELMAkGA1UECxMCZWUxITAfBgNVBAMMGG9wZW52cG5f5a6i5oi356uvX+W4heWTpTEjMCEGCSqGSIb3DQEJARYUb3BlbnZwbl9jbGllbnRAMS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdF5NXwj8DbUg/kteLSYA8bfApZsX5sWYdIS7RAueioPQ+EDpEHsvx69PwNjkzBbBG++vTvZdyYWaTGyrTOoSph1zuV3YJGYOLkrbyZ0INwjAec4tExDkAqLLaxPWoklFErJqCxicbDySQsj54YuIuo9ENfZnDp2I69GPlOq5JYKK5aR1PWp7C4foFs3yeQNeI+n0X5rSU0GZ75q0+MRLiHCADwM/FlrDa8J39uSQLTb4/gy21tz+eNVlk6Ye3/Jwjo3kb/S5IHxd7FzGVPLfx/At3E1PvkRmwZP/FGs+cRi0GK/kA/bxL4DbL7RGiimTtNAw6o5gI3LJ2OHAlAooTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJuL237pnUQ+PYu1j9SSFZKpFaAfnxBXrq3gvdfh45fTQP8S5TcxMuevjwkIkXbQjpABGg8VaEgv/Bgo2eceap0o1mRkz238f8ec7gAD0dSO+iV9KzSMgv9ysUTRM+64E8+u2UPoLv8+yC7+DDeIOQDZoD64Cg2lrqGYGVazORSKojRYaONKzIM7TgUI1/q25NznRVcQiWiDcgo7R75QYFwBhuC0+jls9KUXbg9CA8yApGTVLPTeS5fE6EwLYZD0ecWl6Os1pbtl3BXR+QPH+3yhwwB1V/XBkW/3JWsM+Q9SqXH3sFCo9dm0NROfcrlsVEj5hOB2HrnLSn40zQW5loI=")
	copy(msg.ClientCertData[:], certData)

	// 转换为二进制
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, msg)
	return buf.Bytes()
}

// TestHandleMessage 测试消息处理功能
func TestHandleMessage(t *testing.T) {
	// 创建测试数据
	testData := createRegistMessageBytes(1)

	// 测试处理注册消息
	if err := HandleMessage(TopicRegist, testData); err != nil {
		t.Errorf("HandleMessage() error = %v", err)
	}

	// 打印成功消息
	t.Log("Successfully created and parsed registration message")
}
