package defines

import (
	"os"
	"path/filepath"
)

const (
	CommonCACertPath     = "/var/lib/iot/public/ca.crt"     //该文件是openvpn nanoMQ 的ca证书
	CommonCRLPath        = "/var/lib/iot/public/crl.pem"    //该文件是openvpn nanoMQ 的CRL
	CommonServerCertPath = "/var/lib/iot/public/server.crt" //该文件是openvpn nanoMQ 的服务器证书
	CommonServerKeyPath  = "/var/lib/iot/public/server.key" //该文件是openvpn nanoMQ  的服务器私钥
	CommonCertsDir       = "/var/lib/iot/public"

	//openvpn相关
	SSLVPNDir       = "/var/lib/iot/sslvpn"                     //该目录存放sslvpn api接口生成的json
	OpenVPNDir      = "/var/lib/iot/sslvpn/openvpn"             //该目录存放最终生成的 openvpn配置文件
	OpenVPNCCDDir   = "/var/lib/iot/sslvpn/openvpn/ccd"         //该目录存放最终生成的 openvpn的ccd文件
	OpenVPNMainPath = "/var/lib/iot/sslvpn/openvpn/server.conf" //该文件是openvpn的主配置文件

	//nanomq相关
	NanomqDir = "/var/lib/iot/nanomq" //该目录存放iotmq api的配置文件

)

//有几个目录需要plugin init时新建
//SSLVPNDir OpenVPNDir OpenVPNCCDDir NanomqDir CommonCertsDir

var (
	UserFile         string
	ResFile          string
	AuthFile         string
	SSLVPNConfigFile string
)

func init() {
	UserFile = filepath.Join(SSLVPNDir, "users.json")
	ResFile = filepath.Join(SSLVPNDir, "resources.json")
	AuthFile = filepath.Join(SSLVPNDir, "authorities.json")
	SSLVPNConfigFile = filepath.Join(SSLVPNDir, "sslvpn_config.json")

	//有几个目录需要plugin init时新建
	//PluginSSLVPNDir OpenVPNDir OpenVPNCCDDir NanomqDir PluginCertsDir
	os.MkdirAll(SSLVPNDir, 0755)
	os.MkdirAll(OpenVPNDir, 0755)
	os.MkdirAll(OpenVPNCCDDir, 0755)
	os.MkdirAll(NanomqDir, 0755)
	os.MkdirAll(CommonCertsDir, 0755)

}
