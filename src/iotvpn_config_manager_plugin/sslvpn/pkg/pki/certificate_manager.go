package pki

import (
	"encoding/base64"
	"errors"
	"iotvpn_config_manager_plugin/sslvpn/pkg/defines"
	"iotvpn_config_manager_plugin/sslvpn/pkg/types"
	"os"
)

//前端传入字符串形式的证书文件, 本模块负责解析并保存
/*
{
        "ca": "base64 encode file", //文件内容的base64
        "cert": "base64 encode file", //文件内容的base64
        "key": "base64 encode file",//文件内容的base64
        "key_pwd":"1234",//私钥文件加密口令
        "crl":""//文件内容的base64
}

*/

// CertificateManager 证书管理器
type CertificateManager struct {
	CAPath   string
	CertPath string
	KeyPath  string
	KeyPwd   string
	CrlPath  string
}

// NewCertificateManager 创建新的证书管理器
func NewCertificateManager(keyPwd string) *CertificateManager {
	return &CertificateManager{
		CAPath:   defines.CommonCACertPath,
		CertPath: defines.CommonServerCertPath,
		KeyPath:  defines.CommonServerKeyPath,
		KeyPwd:   keyPwd,
		CrlPath:  defines.CommonCRLPath,
	}
}

// SaveAll 保存4项证书相关文件 ca  cert key crl
func (cm *CertificateManager) SaveAll(jsonData *types.PluginCertManagerJson) error {
	//base64 解码后保存到文件
	ca, err := base64.StdEncoding.DecodeString(jsonData.CA)
	if err != nil {
		return err
	}
	cert, err := base64.StdEncoding.DecodeString(jsonData.Cert)
	if err != nil {
		return err
	}

	key, err := base64.StdEncoding.DecodeString(jsonData.Key)
	if err != nil {
		return err
	}

	crl, err := base64.StdEncoding.DecodeString(jsonData.Crl)
	if err != nil {
		return err
	}

	//保存到文件
	err = os.WriteFile(cm.CAPath, ca, 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(cm.CertPath, cert, 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(cm.KeyPath, key, 0644)
	if err != nil {
		return err
	}
	err = os.WriteFile(cm.CrlPath, crl, 0644)
	if err != nil {
		return err
	}

	return nil
}

// ParseAll 解析4项证书相关文件是否合法 ca  cert key crl
func (cm *CertificateManager) ParseAll(jsonData *types.PluginCertManagerJson) error {

	if !isInvalidCert(jsonData.CA) {
		return errors.New("ca is invalid")
	}
	if !isInvalidCert(jsonData.Cert) {
		return errors.New("cert is invalid")
	}
	if !isValidKey(jsonData.Key, jsonData.KeyPwd) {
		return errors.New("key is invalid")
	}
	if !isValidCRL(jsonData.Crl) {
		return errors.New("crl is invalid")
	}
	return nil
}
