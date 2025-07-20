# MQTT主题和消息定义

## 注册

### 主题名称

- regist

### 消息定义

- uint16_t device_id

  `设备标识`

- char device_ip[32]

  `设备IP地址`

- char device_mask_addr[32]

  `设备子网掩码`

- char device_gw_addr[32]

  `网关地址`

- uint32_t BaudRate  

  `波特率`

- uint32_t WordLength

  `数据位`

- uint32_t StopBits

  `停止位`

- uint32_t Parity

  `检验位`

- uint32_t Mode

  `传输模式`

- uint32_t HwFlowCtl

  `流控`

- uint32_t OverSampling

  `过采样率`

- ComProtocol comprotocol

  `通信协议标准`

  - COM_RS232 = 0
  - COM_RS485 = 1

- char mq_client_id[16]

  `MQTT客户端ID`

- char mq_device_name[16]

  `MQTT设备ID`

- char mq_device_password[8]

  `MQTT设备PIN码`

- uint8_t mqtt_protocol_version  

  `MQTT协议版本`        

  - 3 = MQTT3.1     
  - 4 = MQTT3.1.1

- uint16_t keep_alive_interval

  `MQTT保活时长`

- uint8_t clean_session

  `是否启用持久会话`

- uint8_t will_flag

  `是否启用遗嘱消息`

- char server_ip[32]

  `服务端IP地址`

- uint16_t server_port

  `服务端端口号`

- uint8_t net_protocol

  `传输层协议`

  - 0-UDP
  - 1-TCP

- uint8_t ca_cert_data[1024]

  `ca证书数据`

- uint16_t ca_cert_len

  `ca证书数据长度`

- uint8_t client_cert_data[1024]

  `客户端证书数据`

- uint16_t client_cert_len

  `客户端证书数据长度`

- uint32_t key_update_time

  `密钥更新时间`

- AuthType auth_type

  `认证类别(只支持证书认证)`

  - AUTH_TYPE_CERT = 0

- char collect_item[32]

  `采集数据项`

- char collect_topic[32]

  `采集主题`

- uint32_t collect_cycle

  `采集周期`

- int64_t timestamp

  `时间戳`

## 压力传感器数值

### 主题名称

- pressure

### 消息定义

- uint32_t value

​	`压力值`

- uint16_t device_id

  `设备标识`

## 电机操作指令

### 主题名称

- motor

### 消息定义

- uint8_t command

  `操作指令`

  - 0-停止
  - 1-正转
  - 2-反转

- uint16_t device_id

​	`设备标识`