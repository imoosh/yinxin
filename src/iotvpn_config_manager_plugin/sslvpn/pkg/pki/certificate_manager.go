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

	var (
		ca   []byte
		cert []byte
		key  []byte
		crl  []byte
		err  error
	)

	//base64 解码后保存到文件
	if jsonData.CA != "" {
		ca, _ = base64.StdEncoding.DecodeString(jsonData.CA)
		//保存到文件
		err = os.WriteFile(cm.CAPath, ca, 0644)
		if err != nil {
			return err
		}
	}

	if jsonData.Cert != "" {
		cert, _ = base64.StdEncoding.DecodeString(jsonData.Cert)
		//保存到文件
		err = os.WriteFile(cm.CertPath, cert, 0644)
		if err != nil {
			return err
		}
	}

	if jsonData.Key != "" {
		key, _ = base64.StdEncoding.DecodeString(jsonData.Key)
		//保存到文件
		err = os.WriteFile(cm.KeyPath, key, 0644)
		if err != nil {
			return err
		}
	}

	if jsonData.Crl != "" {
		crl, _ = base64.StdEncoding.DecodeString(jsonData.Crl)
		//保存到文件
		err = os.WriteFile(cm.CrlPath, crl, 0644)
		if err != nil {
			return err
		}
	}

	return nil

}

// ParseAll 解析4项证书相关文件是否合法 ca  cert key crl
func (cm *CertificateManager) ParseAll(jsonData *types.PluginCertManagerJson) error {
	if jsonData.CA != "" {
		if !isInvalidCert(jsonData.CA) {
			return errors.New("ca is invalid")
		}
	}

	if jsonData.Cert != "" {
		if !isInvalidCert(jsonData.Cert) {
			return errors.New("cert is invalid")
		}
	}

	if jsonData.Key != "" {
		if !isValidKey(jsonData.Key, jsonData.KeyPwd) {
			return errors.New("key is invalid")
		}
	}

	if jsonData.Crl != "" {
		if !isValidCRL(jsonData.Crl) {
			return errors.New("crl is invalid")
		}
	}
	return nil
}

func (cm *CertificateManager) GetAll() (*types.PluginCertManagerJson, error) {
	//读取所有证书相关，如果文件不存在，则返回空字符串
	ca, _ := os.ReadFile(cm.CAPath)

	cert, _ := os.ReadFile(cm.CertPath)

	key, _ := os.ReadFile(cm.KeyPath)

	crl, _ := os.ReadFile(cm.CrlPath)

	return &types.PluginCertManagerJson{
		CA:     base64.StdEncoding.EncodeToString(ca),
		Cert:   base64.StdEncoding.EncodeToString(cert),
		Key:    base64.StdEncoding.EncodeToString(key),
		KeyPwd: cm.KeyPwd,
		Crl:    base64.StdEncoding.EncodeToString(crl),
	}, nil
}
