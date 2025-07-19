package pki

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// 证书解析
func PaseCommonNameFromB64(b64Data string) (string, error) {
	var byteslice []byte

	certData, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return "", err
	}

	if certData[0] == '-' { //pem 数据
		block, _ := pem.Decode(certData)
		if block == nil {
			return "", errors.New("failed to decode pem data")
		}
		byteslice = block.Bytes
	} else { //二进制数据
		byteslice = certData
	}

	cert, err := x509.ParseCertificate(byteslice)
	if err != nil {
		return "", err
	}
	return cert.Subject.CommonName, nil
}

func isInvalidCert(b64Data string) bool {
	var byteslice []byte

	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return false
	}

	if data[0] == '-' { //pem 数据
		block, _ := pem.Decode(data)
		if block == nil {
			return false
		}
		byteslice = block.Bytes
	} else { //二进制数据
		byteslice = data
	}

	_, err = x509.ParseCertificate(byteslice)
	if err != nil {
		return false
	}
	return true
}

// 检查是否是合法的key内容
func isValidKey(b64Data string, keyPassword string) bool {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return false // Invalid base64 is an invalid key
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return false // Not a PEM-formatted key
	}

	var keyBytes []byte
	if x509.IsEncryptedPEMBlock(block) {
		if keyPassword == "" {
			return false // Encrypted key requires a password
		}
		keyBytes, err = x509.DecryptPEMBlock(block, []byte(keyPassword))
		if err != nil {
			return false // Failed to decrypt
		}
	} else {
		keyBytes = block.Bytes
	}

	if _, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return true
	}

	return false // None of the parse functions succeeded
}

// 检查是否是合法的crl内容
func isValidCRL(b64Data string) bool {

	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return false
	}

	_, err = x509.ParseCRL(data)
	if err != nil {
		return false
	}
	return true
}
