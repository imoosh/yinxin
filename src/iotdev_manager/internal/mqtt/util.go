package mqtt

import (
	"crypto/tls"
	// "crypto/x509"
	// "fmt"
	// "os"

	"iotdev_manager/internal/config"
)

func tlsConfig(cfg *config.MQTTConfig) (*tls.Config, error) {
	if !cfg.TLS.Enabled {
		return nil, nil
	}

	// // 加载CA证书，用于验证服务器证书
	// caCert, err := os.ReadFile(cfg.TLS.CaCert)
	// if err != nil {
	// 	fmt.Printf("无法读取CA证书: %v\n", err)
	// 	return nil, err
	// }

	// // 创建证书池并添加CA证书
	// caCertPool := x509.NewCertPool()
	// if !caCertPool.AppendCertsFromPEM(caCert) {
	// 	fmt.Println("无法添加CA证书到证书池")
	// 	return nil, err
	// }

	// // 加载客户端证书和私钥
	// clientCert, err := tls.LoadX509KeyPair(cfg.TLS.ClientCert, cfg.TLS.ClientKey)
	// if err != nil {
	// 	fmt.Printf("无法加载客户端证书和私钥: %v\n", err)
	// 	return nil, err
	// }

	// 配置TLS
	tlsConfig := &tls.Config{
		// RootCAs:            caCertPool,
		// Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true, // 生产环境中应设置为false，确保验证服务器证书
		// ClientAuth:         tls.NoClientCert,
		// VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// 	return nil
		// },
		// MinVersion:         tls.VersionTLS12, // 指定最低TLS版本
	}

	return tlsConfig, nil
}
